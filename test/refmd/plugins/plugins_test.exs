defmodule RefMD.PluginsTest do
  use RefMD.DataCase, async: true

  import Ecto.Query

  alias RefMD.Crypto.{Hash, JCS, Signature, Suite}
  alias RefMD.Crypto.Signature.Plugin, as: PluginSignature
  alias RefMD.Devices.Device
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Encryption.KeyDirectory.{Checkpoint, Event}
  alias RefMD.Plugins
  alias RefMD.Storage

  alias RefMD.Plugins.{
    Artifact,
    BundleCandidates,
    PackageEntries,
    Packages,
    PluginActivation,
    PluginBundle,
    PluginBundleCandidate,
    PluginConsentEvent,
    PluginKV,
    PluginPackageEntry,
    PluginRecord,
    RuntimeDescriptors
  }

  alias RefMD.Security.{AuditEvent, Notification}
  alias RefMD.TestCrypto
  alias RefMD.Users.User
  alias RefMD.Workspaces

  describe "plugin application and bundle state" do
    test "rejects application creation without an approved package" do
      %{user: user, workspace: workspace} = account_context()

      assert {:error, changeset} =
               Plugins.create_application(%{
                 workspace_id: workspace.id,
                 plugin_id: "com.example.notes",
                 created_by_user_id: user.id
               })

      assert {"can't be blank", _} = changeset.errors[:package_id]
      assert [] = Plugins.list_workspace_packages(workspace.id)
    end

    test "rejects legacy application creation actor alias" do
      %{user: user, workspace: workspace} = account_context()

      package =
        create_workspace_package!(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.legacy-actor-alias",
          created_by_user_id: user.id
        })

      assert {:error, changeset} =
               %{
                 workspace_id: workspace.id,
                 package_id: package.id,
                 plugin_id: package.plugin_id
               }
               |> Map.put(String.to_atom("installed" <> "_by_user_id"), user.id)
               |> Plugins.create_application()

      assert {"can't be blank", _} = changeset.errors[:created_by_user_id]
    end

    test "rejects duplicate workspace-owned package identity" do
      %{user: user, workspace: workspace} = account_context()

      attrs = %{
        plugin_id: "com.example.package-unique",
        version: "1.0.0",
        owner_scope_kind: "workspace",
        owner_workspace_id: workspace.id,
        created_by_user_id: user.id,
        bundle_hash: hash("workspace-package-bundle"),
        resource_manifest_hash: hash("workspace-package-resources"),
        state_head_hash: "GENESIS"
      }

      assert {:ok, _package} = Packages.create(attrs)
      assert {:error, changeset} = Packages.create(attrs)
      assert errors_on(changeset) != %{}
    end

    test "rejects duplicate user-owned package identity" do
      %{user: user} = account_context()

      attrs = %{
        plugin_id: "com.example.user-package-unique",
        version: "1.0.0",
        owner_scope_kind: "user",
        owner_user_id: user.id,
        created_by_user_id: user.id,
        bundle_hash: hash("user-package-bundle"),
        resource_manifest_hash: hash("user-package-resources"),
        state_head_hash: "GENESIS"
      }

      assert {:ok, _package} = Packages.create(attrs)
      assert {:error, changeset} = Packages.create(attrs)
      assert errors_on(changeset) != %{}
    end

    test "pins the current bundle through the application state head" do
      %{user: user, workspace: workspace, device: device} = account_context()
      old_approval_event_hash = hash("old-approval-event")

      assert {:ok, application} =
               create_plugin_application(%{
                 workspace_id: workspace.id,
                 plugin_id: "com.example.notes",
                 created_by_user_id: user.id,
                 state_head_hash: "approval-head-genesis"
               })

      %{updated: updated, bundle: bundle} = pin_bundle!(application, user, device)

      approval_event_hash = bundle.approval_event_hash

      assert updated.current_bundle_id == bundle.id
      assert updated.state_head_hash == approval_event_hash

      assert {:ok, ^bundle} =
               Plugins.current_bundle_with_pin(application.id, approval_event_hash)

      assert {:error, :plugin_state_head_pin_required} =
               Plugins.current_bundle_with_pin(application.id, nil)

      assert {:error, :plugin_state_rollback} =
               Plugins.current_bundle_with_pin(application.id, old_approval_event_hash)

      assert {:error, :bundle_application_mismatch} =
               Plugins.pin_current_bundle(updated, bundle,
                 expected_state_head_hash: old_approval_event_hash
               )

      application_id = application.id
      assert [%{id: ^application_id}] = Plugins.list_applications(workspace.id)

      assert %{id: ^application_id} = Plugins.get_application(application_id)

      assert {:ok, disabled} = Plugins.update_application(updated, %{enabled: false})
      assert disabled.enabled == false

      assert Repo.get_by(Notification,
               type: "plugin.runtime_disabled",
               recipient_kind: "device",
               recipient_id: device.id
             )

      activation =
        Repo.get_by!(PluginActivation,
          application_id: disabled.id,
          user_id: user.id,
          device_id: device.id
        )

      storage_attrs = %{
        application_id: disabled.id,
        package_id: disabled.package_id,
        workspace_id: workspace.id,
        plugin_id: disabled.plugin_id,
        activation_id: activation.id,
        scope: :workspace,
        scope_id: workspace.id,
        key: "settings",
        ciphertext: <<1, 2, 3>>,
        nonce: <<4, 5, 6>>,
        key_version: 1
      }

      assert {:ok, %PluginKV{} = kv_entry} = Plugins.put_kv(storage_attrs)

      record_attrs =
        storage_attrs
        |> Map.drop([:key, :ciphertext])
        |> Map.merge(%{
          id: "10000000-0000-4000-8000-000000000050",
          kind: "settings-record",
          encrypted_data: <<7, 8, 9>>
        })

      assert {:ok, %PluginRecord{} = record} = Plugins.put_record(record_attrs)

      assert {:error, :plugin_application_disabled} =
               Plugins.current_bundle_with_pin(disabled.id, approval_event_hash)

      assert {:ok, _deleted} = Plugins.delete_application(disabled)

      refute Repo.get(PluginKV, kv_entry.id)
      refute Repo.get(PluginRecord, record.id)

      assert notification =
               Repo.get_by(Notification,
                 type: "plugin.runtime_uninstalled",
                 recipient_kind: "device",
                 recipient_id: device.id
               )

      assert notification.action_ref["workspace_id"] == workspace.id
      assert notification.action_ref["package_id"] == disabled.package_id
      assert notification.action_ref["application_id"] == disabled.id
      assert notification.action_ref["activation_id"] == activation.id
      assert notification.action_ref["plugin_id"] == disabled.plugin_id
      assert notification.action_ref["bundle_hash"] == bundle.bundle_hash
    end

    test "rejects direct bundle creation outside candidate promotion" do
      %{user: user, workspace: workspace} = account_context()

      assert {:ok, application} =
               create_plugin_application(%{
                 workspace_id: workspace.id,
                 plugin_id: "com.example.notes",
                 created_by_user_id: user.id,
                 state_head_hash: "approval-head-genesis"
               })

      assert {:error, :plugin_bundle_candidate_required} =
               bundle_attrs(application, %{})
               |> Plugins.create_bundle()
    end

    test "enforces one activation per user or device scope" do
      %{user: user, workspace: workspace, device: device} = account_context()
      second_device = insert_signing_device!(user, "Second Device")

      assert {:ok, application} =
               create_plugin_application(%{
                 workspace_id: workspace.id,
                 plugin_id: "com.example.notes",
                 created_by_user_id: user.id,
                 state_head_hash: "approval-head-genesis"
               })

      user_activation_attrs = %{
        application_id: application.id,
        user_id: user.id,
        device_id: nil,
        activation_scope_kind: "user",
        enabled: true
      }

      assert {:ok, _activation} = Plugins.create_activation(user_activation_attrs)
      assert {:error, changeset} = Plugins.create_activation(user_activation_attrs)
      assert {"has already been taken", _} = changeset.errors[:application_id]

      device_activation_attrs = %{
        application_id: application.id,
        user_id: user.id,
        device_id: device.id,
        activation_scope_kind: "device",
        enabled: true
      }

      assert {:ok, _activation} = Plugins.create_activation(device_activation_attrs)
      assert {:error, changeset} = Plugins.create_activation(device_activation_attrs)
      assert {"has already been taken", _} = changeset.errors[:application_id]

      assert {:ok, _activation} =
               Plugins.create_activation(%{
                 device_activation_attrs
                 | device_id: second_device.id
               })

      assert {:error, changeset} =
               Plugins.create_activation(%{
                 user_id: user.id,
                 device_id: device.id,
                 activation_scope_kind: "device",
                 enabled: true
               })

      assert {"can't be blank", _} = changeset.errors[:application_id]
    end

    test "rejects pinning candidate-less bundle state" do
      %{user: user, workspace: workspace} = account_context()

      assert {:ok, application} =
               create_plugin_application(%{
                 workspace_id: workspace.id,
                 plugin_id: "com.example.notes",
                 created_by_user_id: user.id,
                 state_head_hash: "approval-head-genesis"
               })

      bundle = %PluginBundle{
        application_id: application.id,
        workspace_id: workspace.id,
        approval_event_hash: hash("approval-event")
      }

      assert {:error, :plugin_bundle_candidate_required} =
               Plugins.pin_current_bundle(application, bundle)
    end

    test "rejects pinning bundle state that no longer matches the candidate" do
      %{user: user, workspace: workspace, device: device} = account_context()

      assert {:ok, application} =
               create_plugin_application(%{
                 workspace_id: workspace.id,
                 plugin_id: "com.example.notes",
                 created_by_user_id: user.id,
                 state_head_hash: "approval-head-genesis"
               })

      %{updated: updated, bundle: bundle} = pin_bundle!(application, user, device)

      assert {:error, :plugin_bundle_runtime_hash_mismatch} =
               Plugins.pin_current_bundle(updated, %{
                 bundle
                 | bundle_hash: hash("tampered-bundle")
               })
    end

    test "rejects bundle state with non-canonical hash fields" do
      %{user: user, workspace: workspace} = account_context()

      assert {:ok, application} =
               create_plugin_application(%{
                 workspace_id: workspace.id,
                 plugin_id: "com.example.notes",
                 created_by_user_id: user.id,
                 state_head_hash: "approval-head-genesis"
               })

      attrs =
        application
        |> bundle_attrs(%{
          candidate_id: Ecto.UUID.generate(),
          bundle_hash: "not-a-hash"
        })
        |> Map.put(:hybrid_signature, %{"test" => "signature"})

      assert changeset = PluginBundle.changeset(%PluginBundle{}, attrs)

      assert %{bundle_hash: ["must be a BLAKE3 base64url hash"]} = errors_on(changeset)
    end

    test "rejects non-canonical candidate and bundle resource manifest hashes" do
      %{user: user, workspace: workspace, device: device} = account_context()

      assert {:ok, application} =
               create_plugin_application(%{
                 workspace_id: workspace.id,
                 plugin_id: "com.example.notes",
                 created_by_user_id: user.id,
                 state_head_hash: "approval-head-genesis"
               })

      manifest = %{"id" => application.plugin_id, "version" => "1.0.0"}
      manifest_json_bytes = Jason.encode!(manifest)
      main_js = "export default {}"
      styles_css = ""

      candidate_attrs = %{
        package_id: application.package_id,
        workspace_id: workspace.id,
        plugin_id: application.plugin_id,
        version: "1.0.0",
        source_kind: "local_upload",
        source_url_hash: "NO_SOURCE_URL",
        archive_hash: hash("archive"),
        manifest_json: manifest,
        manifest_json_bytes: manifest_json_bytes,
        main_js: main_js,
        styles_css: styles_css,
        manifest_hash: hash(manifest_json_bytes),
        main_js_hash: hash(main_js),
        styles_css_hash: hash(styles_css),
        resource_manifest: [],
        resource_manifest_hash: "not-a-hash",
        bundle_hash: Artifact.bundle_hash(main_js, styles_css, manifest_json_bytes),
        permissions_hash: semantic_hash([]),
        endpoint_hash: semantic_hash([]),
        renderer_slots_hash: semantic_hash([]),
        document_scope_hash: semantic_hash([]),
        validation_status: "valid",
        validation_errors: [],
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      assert candidate_changeset =
               PluginBundleCandidate.changeset(%PluginBundleCandidate{}, candidate_attrs)

      assert %{resource_manifest_hash: ["must be a BLAKE3 base64url hash"]} =
               errors_on(candidate_changeset)

      bundle_attrs =
        application
        |> bundle_attrs(%{
          candidate_id: Ecto.UUID.generate(),
          resource_manifest_hash: "not-a-hash"
        })
        |> Map.put(:hybrid_signature, %{"test" => "signature"})

      assert bundle_changeset = PluginBundle.changeset(%PluginBundle{}, bundle_attrs)

      assert %{resource_manifest_hash: ["must be a BLAKE3 base64url hash"]} =
               errors_on(bundle_changeset)
    end

    test "creates inert artifact candidates and promotes only approved bytes" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default {}"
        })

      assert {:ok, %PluginBundleCandidate{} = candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 package_id: application.package_id,
                 workspace_id: workspace.id,
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      assert candidate.source_kind == "local_upload"
      assert candidate.source_url_hash == "NO_SOURCE_URL"
      assert candidate.styles_css_hash == hash("")

      fetch_requested = Repo.get_by!(AuditEvent, type: "plugin.artifact.fetch_requested")
      assert fetch_requested.correlation["source_kind"] == "local_upload"
      assert fetch_requested.correlation["canonical_source_host"] == nil

      fetch_completed = Repo.get_by!(AuditEvent, type: "plugin.artifact.fetch_completed")
      assert fetch_completed.correlation["source_kind"] == "local_upload"
      assert fetch_completed.correlation["archive_hash"] == candidate.archive_hash
      assert fetch_completed.correlation["bundle_hash"] == candidate.bundle_hash
      assert fetch_completed.correlation["manifest_hash"] == candidate.manifest_hash

      assert Repo.get_by!(AuditEvent, type: "plugin.bundle.candidate_created")

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:error, :plugin_bundle_approval_hash_mismatch} =
               Plugins.promote_bundle_candidate(candidate, %{
                 approval
                 | approval_event_hash: hash("wrong-approval")
               })

      assert {:error, :plugin_bundle_approval_signature_invalid} =
               Plugins.promote_bundle_candidate(candidate, %{
                 approval
                 | hybrid_signature: %{"sig" => "ok"}
               })

      assert Repo.get_by(AuditEvent,
               type: "plugin.bundle.rejected",
               action: %{
                 "operation" => "plugin.bundle.reject",
                 "result" => "denied",
                 "reason_code" => "plugin_bundle_approval_hash_mismatch"
               }
             )

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)
      assert package.current_bundle_id
      assert package.state_head_hash == approval.approval_event_hash
      assert Repo.get_by(AuditEvent, type: "plugin.bundle.approved")
      assert Repo.get_by(AuditEvent, type: "plugin.bundle.promoted")
      assert is_nil(Plugins.get_application(application.id).current_bundle_id)

      refute Repo.get_by(Notification,
               type: "plugin.consent_required",
               recipient_kind: "user",
               recipient_id: user.id
             )

      refute Repo.get_by(Notification,
               type: "plugin.runtime_updated",
               recipient_kind: "device",
               recipient_id: device.id
             )

      assert {:error, :plugin_bundle_approval_rollback} =
               Plugins.promote_bundle_candidate(candidate, approval)

      assert Repo.aggregate(
               from(e in AuditEvent, where: e.type == "plugin.bundle.rejected"),
               :count
             ) >= 3

      assert {:ok, %{application: updated}} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      assert {:ok, bundle} =
               Plugins.current_bundle_with_pin(updated.id, approval.approval_event_hash)

      assert bundle.bundle_hash == candidate.bundle_hash
      assert bundle.candidate_id == candidate.id
      assert {:ok, bytes} = PackageEntries.bundle_bytes(bundle.id)
      assert bytes["main.js"] == candidate.main_js
      assert Map.get(bytes, "styles.css", "") == candidate.styles_css
      assert bytes["manifest.json"] == candidate.manifest_json_bytes

      update_archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.1.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default { version: '1.1.0' }"
        })

      assert {:ok, %PluginBundleCandidate{}} =
               Plugins.create_local_bundle_candidate(update_archive_path, %{
                 application_id: updated.id,
                 workspace_id: workspace.id,
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      assert Repo.get_by(AuditEvent, type: "plugin.bundle.update_available")
    end

    test "package update approval advances applied application runtime and requires fresh consent" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.update-runtime",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.update-runtime","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default { version: '1.0.0' }"
        })

      {:ok, candidate} =
        Plugins.create_local_bundle_candidate(archive_path, %{
          package_id: application.package_id,
          workspace_id: workspace.id,
          created_by_user_id: user.id,
          created_by_device_id: device.id
        })

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

      assert {:ok, %{application: applied, activation: activation}} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      assert {:ok, old_bundle} =
               Plugins.current_bundle_with_pin(applied.id, package.state_head_hash)

      assert {:ok, old_consent} =
               Plugins.append_consent_event(
                 consent_attrs(%{
                   package_id: applied.package_id,
                   application_id: applied.id,
                   activation_id: activation.id,
                   workspace_id: workspace.id,
                   plugin_id: applied.plugin_id,
                   owner_scope_kind: "workspace",
                   application_scope_kind: applied.application_scope_kind,
                   version: old_bundle.version,
                   bundle_hash: old_bundle.bundle_hash,
                   manifest_hash: old_bundle.manifest_hash,
                   permissions_hash: old_bundle.permissions_hash,
                   endpoint_hash: old_bundle.endpoint_hash,
                   document_scope_hash: old_bundle.document_scope_hash,
                   user_id: user.id,
                   device_id: device.id,
                   signer_user_id: user.id,
                   signer_device_id: device.id
                 })
               )

      assert {:ok, _payload} =
               Plugins.runtime_bundle_with_pins(
                 applied.id,
                 workspace.id,
                 user.id,
                 device.id,
                 applied.state_head_hash,
                 old_consent.event_hash
               )

      update_archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.update-runtime","version":"1.1.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default { version: '1.1.0' }"
        })

      {:ok, update_candidate} =
        Plugins.create_local_bundle_candidate(update_archive_path, %{
          package_id: package.id,
          workspace_id: workspace.id,
          created_by_user_id: user.id,
          created_by_device_id: device.id
        })

      update_approval =
        approval_attrs(update_candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 2,
          previous_approval_event_hash: package.state_head_hash
        })

      assert {:ok, updated_package} =
               Plugins.promote_bundle_candidate(update_candidate, update_approval)

      assert updated_package.version == "1.1.0"
      updated_application = Plugins.get_application(applied.id)
      assert updated_application.current_bundle_id == updated_package.current_bundle_id
      assert updated_application.state_head_hash == updated_package.state_head_hash
      refute updated_application.current_bundle_id == old_bundle.id

      assert {:error, :plugin_state_rollback} =
               Plugins.runtime_bundle_with_pins(
                 applied.id,
                 workspace.id,
                 user.id,
                 device.id,
                 applied.state_head_hash,
                 old_consent.event_hash
               )

      assert {:error, :plugin_consent_rollback} =
               Plugins.runtime_bundle_with_pins(
                 applied.id,
                 workspace.id,
                 user.id,
                 device.id,
                 updated_application.state_head_hash,
                 old_consent.event_hash
               )

      assert [] = Plugins.list_runtime_descriptors(workspace.id, user.id, device.id)

      assert [%{bundle_hash: bundle_hash}] =
               Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)

      assert bundle_hash == update_candidate.bundle_hash

      assert Repo.get_by(Notification,
               type: "plugin.runtime_updated",
               recipient_kind: "device",
               recipient_id: device.id
             )

      assert Repo.get_by(Notification,
               type: "plugin.consent_required",
               recipient_kind: "user",
               recipient_id: user.id
             )
    end

    @tag :bundle_update_candidate
    test "local candidate without explicit package id reuses existing owner plugin package" do
      %{user: user, workspace: workspace, device: device} = account_context()

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.auto-update","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default { version: '1.0.0' }"
        })

      {:ok, candidate} =
        Plugins.create_local_bundle_candidate(archive_path, %{
          workspace_id: workspace.id,
          created_by_user_id: user.id,
          created_by_device_id: device.id
        })

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

      assert {:ok, %{application: applied}} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      update_archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.auto-update","version":"1.1.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default { version: '1.1.0' }"
        })

      {:ok, update_candidate} =
        Plugins.create_local_bundle_candidate(update_archive_path, %{
          workspace_id: workspace.id,
          created_by_user_id: user.id,
          created_by_device_id: device.id
        })

      assert update_candidate.package_id == package.id

      update_approval =
        approval_attrs(update_candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 2,
          previous_approval_event_hash: package.state_head_hash
        })

      assert {:ok, updated_package} =
               Plugins.promote_bundle_candidate(update_candidate, update_approval)

      assert updated_package.version == "1.1.0"
      updated_application = Plugins.get_application(applied.id)
      assert updated_application.current_bundle_id == updated_package.current_bundle_id
      assert updated_application.state_head_hash == updated_package.state_head_hash

      assert Repo.get_by(Notification,
               type: "plugin.runtime_updated",
               recipient_kind: "device",
               recipient_id: device.id
             )
    end

    @tag :bundle_update_candidate
    test "user package update exposes an existing workspace runtime target for state pinning" do
      %{user: user, workspace: workspace, device: device} = account_context()
      device = TestCrypto.ensure_test_user_rrp_key_directory!(user.id, device)

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["user"],"defaultOwnerScope":"user","workspaceApplication":"optional"},"id":"com.example.personal-update","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default { version: '1.0.0' }"
        })

      {:ok, candidate} =
        Plugins.create_local_bundle_candidate(archive_path, %{
          owner_scope_kind: "user",
          created_by_user_id: user.id,
          created_by_device_id: device.id
        })

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

      assert {:ok, %{application: applied, activation: activation}} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      update_archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["user"],"defaultOwnerScope":"user","workspaceApplication":"optional"},"id":"com.example.personal-update","version":"1.1.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default { version: '1.1.0' }"
        })

      {:ok, update_candidate} =
        Plugins.create_local_bundle_candidate(update_archive_path, %{
          owner_scope_kind: "user",
          created_by_user_id: user.id,
          created_by_device_id: device.id
        })

      assert update_candidate.package_id == package.id

      update_approval =
        approval_attrs(update_candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 2,
          previous_approval_event_hash: package.state_head_hash
        })

      assert {:ok, updated_package} =
               Plugins.promote_bundle_candidate(update_candidate, update_approval)

      assert {:ok, %{application: runtime_application, activation: runtime_activation}} =
               Plugins.ensure_existing_personal_package_runtime(
                 workspace.id,
                 updated_package,
                 user.id,
                 device.id
               )

      assert runtime_application.id == applied.id
      assert runtime_application.state_head_hash == updated_package.state_head_hash
      assert runtime_application.current_bundle_id == updated_package.current_bundle_id
      assert runtime_activation.id == activation.id
    end

    test "local upload acquisition audit failure blocks candidate creation" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default {}"
        })

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      assert {:error, :audit_failed} =
               BundleCandidates.create_local(archive_path, attrs,
                 record_fetch_requested: fn _attrs -> {:error, :audit_failed} end
               )

      assert Repo.aggregate(PluginBundleCandidate, :count, :id) == 0
      refute Repo.get_by(AuditEvent, type: "plugin.bundle.candidate_created")
    end

    test "rejects promotion when candidate package bytes are missing from configured storage" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default {}"
        })

      assert {:ok, %PluginBundleCandidate{} = candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 package_id: application.package_id,
                 workspace_id: workspace.id,
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      entry =
        Repo.get_by!(PluginPackageEntry, candidate_id: candidate.id, logical_path: "main.js")

      assert uuid_v7?(entry.id)
      assert entry.storage_path == "plugin-packages/#{entry.id}"

      assert :ok = Storage.delete(entry.storage_path)

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:error, :plugin_package_entry_missing} =
               Plugins.promote_bundle_candidate(candidate, approval)
    end

    test "cleans package entry storage when candidate entry creation fails after partial writes" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default {}"
        })

      assert {:ok, %PluginBundleCandidate{} = candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 application_id: application.id,
                 workspace_id: workspace.id,
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      duplicate_resource = %{
        entry_kind: "resource",
        logical_path: "resources/cleanup.txt",
        resource_kind: "text",
        media_type: "text/plain",
        bytes: "cleanup"
      }

      assert {:error, %Ecto.Changeset{}} =
               PackageEntries.create_candidate_entries(candidate, [
                 duplicate_resource,
                 duplicate_resource
               ])

      assert [
               %PluginPackageEntry{status: "orphan_pending_delete", storage_path: storage_path}
             ] =
               Repo.all(
                 from(e in PluginPackageEntry,
                   where:
                     e.candidate_id == ^candidate.id and
                       e.logical_path == "resources/cleanup.txt"
                 )
               )

      assert {:error, :not_found} = Storage.get(storage_path)
    end

    test "cleans package entry storage before a surrounding candidate transaction rolls back" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default {}"
        })

      assert {:ok, %PluginBundleCandidate{} = candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 application_id: application.id,
                 workspace_id: workspace.id,
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      resource = %{
        entry_kind: "resource",
        logical_path: "resources/rollback-cleanup.txt",
        resource_kind: "text",
        media_type: "text/plain",
        bytes: "cleanup"
      }

      path_holder = start_supervised!({Agent, fn -> nil end})

      {:error, :forced_rollback} =
        Repo.transaction(fn ->
          {:ok, entries} = PackageEntries.create_candidate_entries(candidate, [resource])
          [entry] = entries
          Agent.update(path_holder, fn _ -> entry.storage_path end)
          assert {:ok, "cleanup"} = Storage.get(entry.storage_path)
          PackageEntries.cleanup_entries(entries)
          Repo.rollback(:forced_rollback)
        end)

      assert Repo.get_by(PluginPackageEntry,
               candidate_id: candidate.id,
               logical_path: "resources/rollback-cleanup.txt"
             ) == nil

      storage_path = Agent.get(path_holder, & &1)
      assert {:error, :not_found} = Storage.get(storage_path)
    end

    test "creates a first-install candidate without inserting an application until approval" do
      %{user: user, workspace: workspace, device: device} = account_context()

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.first","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default {}"
        })

      assert {:ok, %PluginBundleCandidate{} = candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 workspace_id: workspace.id,
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      assert candidate.plugin_id == "com.example.first"
      assert candidate.workspace_id == workspace.id
      refute candidate.application_id

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      approval_subject = Plugins.plugin_bundle_approval_subject(candidate, approval)
      assert approval_subject["owner_scope_kind"] == "workspace"
      assert approval_subject["owner_workspace_id"] == workspace.id
      assert approval_subject["application_scope_kind"] == "workspace"
      assert approval_subject["workspace_id"] == workspace.id
      refute Map.has_key?(approval_subject, "owner_user_id")
      refute Enum.any?(approval_subject, fn {_key, value} -> is_nil(value) end)

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)
      assert package.plugin_id == candidate.plugin_id
      assert package.current_bundle_id
      assert package.state_head_hash == approval.approval_event_hash
      assert [] = Plugins.list_applications(workspace.id)

      assert {:ok, %{application: application}} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      assert application.plugin_id == candidate.plugin_id
      assert application.current_bundle_id
      assert application.state_head_hash == approval.approval_event_hash

      assert {:ok, bundle} =
               Plugins.current_bundle_with_pin(application.id, application.state_head_hash)

      assert bundle.candidate_id == candidate.id
      assert is_nil(bundle.application_id)
      assert bundle.workspace_id == workspace.id
    end

    test "approves a user-owned personal package without a separate workspace apply action" do
      %{user: user, workspace: workspace, device: device} = account_context()
      device = TestCrypto.ensure_test_user_rrp_key_directory!(user.id, device)

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["user"],"defaultOwnerScope":"user","workspaceApplication":"none"},"id":"com.example.vim","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default {}"
        })

      assert {:ok, %PluginBundleCandidate{} = candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 owner_scope_kind: "user",
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      assert candidate.owner_scope_kind == "user"
      assert candidate.owner_user_id == user.id
      assert is_nil(candidate.owner_workspace_id)
      assert is_nil(candidate.workspace_id)
      assert is_nil(candidate.application_id)

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      approval_subject = Plugins.plugin_bundle_approval_subject(candidate, approval)
      assert approval_subject["owner_scope_kind"] == "user"
      assert approval_subject["owner_user_id"] == user.id
      refute Map.has_key?(approval_subject, "owner_workspace_id")
      refute Map.has_key?(approval_subject, "application_scope_kind")
      refute Map.has_key?(approval_subject, "workspace_id")
      refute Enum.any?(approval_subject, fn {_key, value} -> is_nil(value) end)

      scoped_user_subject =
        approval_subject
        |> Map.put("application_scope_kind", "workspace")
        |> Map.put("workspace_id", workspace.id)

      assert_raise ArgumentError, "unexpected_keys", fn ->
        PluginSignature.build_plugin_bundle_approval_transcript!(%{
          actor: approval_signing_actor(candidate, approval),
          approval: scoped_user_subject
        })
      end

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

      assert package.owner_scope_kind == "user"
      assert package.owner_user_id == user.id
      assert is_nil(package.owner_workspace_id)
      assert is_binary(package.current_bundle_id)
      assert [%{id: package_id}] = Plugins.list_user_packages(user.id)
      assert package_id == package.id

      bundle = Repo.get!(PluginBundle, package.current_bundle_id)
      assert bundle.package_id == package.id
      assert is_nil(bundle.workspace_id)
      assert is_nil(bundle.application_id)

      assert {:error, activation_changeset} =
               Plugins.create_activation(%{
                 package_id: package.id,
                 user_id: user.id,
                 device_id: device.id,
                 activation_scope_kind: "device",
                 enabled: true
               })

      assert {"can't be blank", _} = activation_changeset.errors[:application_id]
      assert [] = Plugins.list_activations(user.id, device.id)

      assert {:error, :application_not_found} =
               Plugins.runtime_bundle_with_pins(
                 package.id,
                 workspace.id,
                 user.id,
                 device.id,
                 package.state_head_hash,
                 "NO_CONSENT_REQUIRED"
               )

      assert [
               %{
                 application_id: application_id,
                 activation_id: activation_id,
                 owner_scope_kind: "user",
                 application_scope_kind: "workspace",
                 state_head_hash: state_head_hash,
                 consent_head_hash: nil
               }
             ] = Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)

      application = Plugins.get_application(application_id)
      activation = Repo.get!(PluginActivation, activation_id)

      assert application.package_id == package.id
      assert application.plugin_id == package.plugin_id
      assert application.application_mode == "user_applied"
      assert application.workspace_policy_result == "allowed"
      assert application.current_bundle_id == package.current_bundle_id
      assert application.state_head_hash == package.state_head_hash
      assert state_head_hash == package.state_head_hash
      assert activation.application_id == application.id

      assert Enum.any?(
               Plugins.list_activations(user.id, device.id),
               &(&1.application_id == application.id)
             )

      consent_base_attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        plugin_id: application.plugin_id,
        version: bundle.version,
        bundle_hash: bundle.bundle_hash,
        manifest_hash: bundle.manifest_hash,
        permissions_hash: bundle.permissions_hash,
        endpoint_hash: bundle.endpoint_hash,
        document_scope_hash: bundle.document_scope_hash,
        user_id: user.id,
        device_id: device.id,
        signer_user_id: user.id,
        signer_device_id: device.id
      }

      wrong_scope_attrs = consent_attrs(consent_base_attrs)

      wrong_scope_subject =
        wrong_scope_attrs
        |> Plugins.consent_subject()
        |> Map.put("owner_scope_kind", "workspace")
        |> Map.put("application_scope_kind", "user")

      assert {:error, :plugin_consent_event_hash_mismatch} =
               Plugins.append_consent_event(
                 wrong_scope_attrs
                 |> Map.put(:owner_scope_kind, "workspace")
                 |> Map.put(:application_scope_kind, "user")
                 |> Map.put(
                   :event_hash,
                   Hash.blake3_base64url(JCS.canonical_bytes!(wrong_scope_subject))
                 )
               )

      assert {:ok, consent} = Plugins.append_consent_event(consent_attrs(consent_base_attrs))

      assert [
               %{
                 application_id: application_id,
                 activation_id: activation_id,
                 owner_scope_kind: "user",
                 state_head_hash: state_head_hash,
                 consent_head_hash: consent_head_hash
               }
             ] = Plugins.list_runtime_descriptors(workspace.id, user.id, device.id)

      assert application_id == application.id
      assert activation_id == activation.id
      assert state_head_hash == package.state_head_hash
      assert consent_head_hash == consent.event_hash

      assert {:ok, _workspace} =
               Workspaces.update_workspace(workspace, %{
                 plugin_user_policy: %{"default_mode" => "deny_all"}
               })

      denied_application = Plugins.get_application(application.id)
      assert denied_application.workspace_policy_result == "denied"
      assert [] = Plugins.list_runtime_descriptors(workspace.id, user.id, device.id)
    end

    test "workspace user plugin policy denies personal package application without deleting package" do
      %{user: user, workspace: workspace, device: device} = account_context()
      device = TestCrypto.ensure_test_user_rrp_key_directory!(user.id, device)

      {:ok, workspace} =
        Workspaces.update_workspace(workspace, %{
          plugin_user_policy: %{"default_mode" => "deny_all"}
        })

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["user"],"defaultOwnerScope":"user","workspaceApplication":"none"},"id":"com.example.denied-personal","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default {}"
        })

      assert {:ok, candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 owner_scope_kind: "user",
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

      assert {:error, :plugin_workspace_policy_denied} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      assert [%{id: package_id}] = Plugins.list_user_packages(user.id)
      assert package_id == package.id
      assert [] = Plugins.list_applications(workspace.id)
      assert [] = Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)
    end

    test "workspace user plugin policy allow-list permits high-risk personal package" do
      %{user: user, workspace: workspace, device: device} = account_context()
      device = TestCrypto.ensure_test_user_rrp_key_directory!(user.id, device)

      {:ok, workspace} =
        Workspaces.update_workspace(workspace, %{
          plugin_user_policy: %{
            "allowed_plugin_ids" => ["com.example.allowed-export"]
          }
        })

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["user"],"defaultOwnerScope":"user","workspaceApplication":"optional"},"id":"com.example.allowed-export","version":"1.0.0","permissions":["network:fetch"],"network":{"endpoints":[{"id":"api","url":"https://api.example.com/export","routes":["proxy"],"methods":["POST"],"bodySchema":"json"}]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default {}"
        })

      assert {:ok, candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 owner_scope_kind: "user",
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

      assert {:ok, %{application: application}} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      assert application.workspace_policy_result == "allowed"

      assert [%{application_id: application_id}] =
               Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)

      assert application_id == application.id
    end

    test "rejects workspace-bound user-owned candidates" do
      %{user: user, workspace: workspace, device: device} = account_context()

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["user"],"defaultOwnerScope":"user","workspaceApplication":"optional"},"id":"com.example.invalid-scope","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default {}"
        })

      assert {:error, %Ecto.Changeset{} = changeset} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 owner_scope_kind: "user",
                 workspace_id: workspace.id,
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      assert {"must match owner scope", _} = changeset.errors[:workspace_id]
    end

    test "requires workspace approval before high-risk user-owned package runtime issuance" do
      %{user: user, workspace: workspace, device: device} = account_context()
      device = TestCrypto.ensure_test_user_rrp_key_directory!(user.id, device)

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["user"],"defaultOwnerScope":"user","workspaceApplication":"optional"},"id":"com.example.export","version":"1.0.0","permissions":["network:fetch"],"network":{"endpoints":[{"id":"api","url":"https://api.example.com/export","routes":["proxy"],"methods":["POST"],"bodySchema":"json"}]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default {}"
        })

      assert {:ok, %PluginBundleCandidate{} = candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 owner_scope_kind: "user",
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

      assert {:ok, %{application: application}} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      assert application.application_mode == "user_applied"
      assert application.workspace_policy_result == "needs_admin_review"
      assert [] = Plugins.list_runtime_descriptors(workspace.id, user.id, device.id)
      assert [] = Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)

      assert {:error, :plugin_workspace_policy_denied} =
               Plugins.runtime_bundle_with_pins(
                 application.id,
                 workspace.id,
                 user.id,
                 device.id,
                 application.state_head_hash,
                 "GENESIS"
               )
    end

    test "preserves workspace approval when reapplying after activation deletion" do
      %{user: user, workspace: workspace, device: device} = account_context()
      device = TestCrypto.ensure_test_user_rrp_key_directory!(user.id, device)

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["user"],"defaultOwnerScope":"user","workspaceApplication":"optional"},"id":"com.example.reapply-approved-user-plugin","version":"1.0.0","permissions":["network:fetch"],"network":{"endpoints":[{"id":"api","url":"https://api.example.com/export","routes":["proxy"],"methods":["POST"],"bodySchema":"json"}]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default {}"
        })

      assert {:ok, %PluginBundleCandidate{} = candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 owner_scope_kind: "user",
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

      assert {:ok, %{application: application, activation: activation}} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      assert application.workspace_policy_result == "needs_admin_review"

      assert {:ok, allowed_application} =
               Plugins.update_application(application, %{workspace_policy_result: "allowed"})

      assert [%{activation_id: first_activation_id}] =
               Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)

      assert first_activation_id == activation.id
      assert {:ok, deleted_activation} = Plugins.delete_activation(activation)
      assert deleted_activation.deleted_at
      assert [] = Plugins.list_runtime_descriptors(workspace.id, user.id, device.id)
      assert [] = Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)

      assert {:ok, %{application: reapplied_application, activation: reapplied_activation}} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      assert reapplied_application.id == allowed_application.id
      assert reapplied_application.workspace_policy_result == "allowed"
      refute reapplied_activation.id == activation.id

      assert [%{activation_id: reactivation_id}] =
               Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)

      assert reactivation_id == reapplied_activation.id
    end

    test "requires workspace approval before user-owned Host UI permission runtime issuance" do
      %{user: user, workspace: workspace, device: device} = account_context()
      device = TestCrypto.ensure_test_user_rrp_key_directory!(user.id, device)

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["user"],"defaultOwnerScope":"user","workspaceApplication":"optional"},"id":"com.example.sidebar-user-plugin","version":"1.0.0","permissions":["ui:sidebar"],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default {}"
        })

      assert {:ok, %PluginBundleCandidate{} = candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 owner_scope_kind: "user",
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

      assert {:ok, %{application: application}} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      assert application.application_mode == "user_applied"
      assert application.workspace_policy_result == "needs_admin_review"
      assert [] = Plugins.list_runtime_descriptors(workspace.id, user.id, device.id)
      assert [] = Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)

      assert {:error, :plugin_workspace_policy_denied} =
               Plugins.runtime_bundle_with_pins(
                 application.id,
                 workspace.id,
                 user.id,
                 device.id,
                 application.state_head_hash,
                 "GENESIS"
               )
    end

    test "user-owned package updates recalculate workspace policy for existing applications" do
      %{user: user, workspace: workspace, device: device} = account_context()
      device = TestCrypto.ensure_test_user_rrp_key_directory!(user.id, device)

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["user"],"defaultOwnerScope":"user","workspaceApplication":"optional"},"id":"com.example.escalating-user-plugin","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default { version: '1.0.0' }"
        })

      assert {:ok, candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 owner_scope_kind: "user",
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

      assert {:ok, %{application: application}} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      assert application.workspace_policy_result == "allowed"

      update_archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["user"],"defaultOwnerScope":"user","workspaceApplication":"optional"},"id":"com.example.escalating-user-plugin","version":"1.1.0","permissions":["network:fetch"],"network":{"endpoints":[{"id":"api","url":"https://api.example.com/export","routes":["proxy"],"methods":["POST"],"bodySchema":"json"}]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default { version: '1.1.0' }"
        })

      assert {:ok, update_candidate} =
               Plugins.create_local_bundle_candidate(update_archive_path, %{
                 package_id: package.id,
                 owner_scope_kind: "user",
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      update_approval =
        approval_attrs(update_candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 2,
          previous_approval_event_hash: package.state_head_hash
        })

      assert {:ok, updated_package} =
               Plugins.promote_bundle_candidate(update_candidate, update_approval)

      assert updated_package.version == "1.1.0"
      updated_application = Plugins.get_application(application.id)
      assert updated_application.current_bundle_id == updated_package.current_bundle_id
      assert updated_application.state_head_hash == updated_package.state_head_hash
      assert updated_application.workspace_policy_result == "needs_admin_review"
      assert [] = Plugins.list_runtime_descriptors(workspace.id, user.id, device.id)
      assert [] = Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)

      assert {:error, :plugin_workspace_policy_denied} =
               Plugins.runtime_bundle_with_pins(
                 application.id,
                 workspace.id,
                 user.id,
                 device.id,
                 updated_application.state_head_hash,
                 "GENESIS"
               )
    end

    test "workspace policy denial blocks runtime bundle and plugin storage authorization" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.storage-policy",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      %{updated: application, bundle: bundle} =
        pin_bundle!(application, user, device, ["storage:write:workspace"])

      assert {:ok, consent} =
               Plugins.append_consent_event(
                 consent_attrs(%{
                   application_id: application.id,
                   workspace_id: workspace.id,
                   plugin_id: application.plugin_id,
                   version: bundle.version,
                   bundle_hash: bundle.bundle_hash,
                   manifest_hash: bundle.manifest_hash,
                   permissions_hash: bundle.permissions_hash,
                   endpoint_hash: bundle.endpoint_hash,
                   document_scope_hash: bundle.document_scope_hash,
                   user_id: user.id,
                   device_id: device.id,
                   signer_user_id: user.id,
                   signer_device_id: device.id
                 })
               )

      assert [_descriptor] = Plugins.list_runtime_descriptors(workspace.id, user.id, device.id)

      assert {:ok, _payload} =
               Plugins.runtime_bundle_with_pins(
                 application.id,
                 workspace.id,
                 user.id,
                 device.id,
                 application.state_head_hash,
                 consent.event_hash
               )

      activation = Repo.get!(PluginActivation, consent.activation_id)

      capability_grant_id =
        RuntimeDescriptors.capability_grant_id(
          application,
          bundle,
          activation,
          consent,
          user.id,
          device.id
        )

      frame_generation =
        current_frame_generation!(
          application,
          bundle,
          activation,
          consent,
          user.id,
          device.id,
          capability_grant_id
        )

      storage_context = %{
        application_id: application.id,
        plugin_id: application.plugin_id,
        workspace_id: workspace.id,
        surface: "workspace",
        operation: "write",
        user_id: user.id,
        device_id: device.id,
        state_head_hash: application.state_head_hash,
        consent_head_hash: consent.event_hash,
        capability_grant_id: capability_grant_id,
        consent_epoch: consent.consent_epoch,
        frame_generation: frame_generation
      }

      assert {:ok, _context} = Plugins.authorize_storage_context(storage_context)

      assert {:ok, denied} =
               Plugins.update_application(application, %{workspace_policy_result: "denied"})

      assert denied.workspace_policy_result == "denied"

      assert Repo.get_by(Notification,
               type: "plugin.runtime_disabled",
               recipient_kind: "device",
               recipient_id: device.id
             )

      assert [] = Plugins.list_runtime_descriptors(workspace.id, user.id, device.id)
      assert [] = Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)

      assert {:error, :plugin_workspace_policy_denied} =
               Plugins.runtime_bundle_with_pins(
                 application.id,
                 workspace.id,
                 user.id,
                 device.id,
                 application.state_head_hash,
                 consent.event_hash
               )

      assert {:error, :forbidden, "plugin_workspace_policy_denied"} =
               Plugins.authorize_storage_context(storage_context)
    end

    test "disabled activation blocks stale runtime pins and plugin storage authorization" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.activation-policy",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      %{updated: application, bundle: bundle} =
        pin_bundle!(application, user, device, ["storage:write:workspace"])

      assert {:ok, consent} =
               Plugins.append_consent_event(
                 consent_attrs(%{
                   application_id: application.id,
                   workspace_id: workspace.id,
                   plugin_id: application.plugin_id,
                   version: bundle.version,
                   bundle_hash: bundle.bundle_hash,
                   manifest_hash: bundle.manifest_hash,
                   permissions_hash: bundle.permissions_hash,
                   endpoint_hash: bundle.endpoint_hash,
                   document_scope_hash: bundle.document_scope_hash,
                   user_id: user.id,
                   device_id: device.id,
                   signer_user_id: user.id,
                   signer_device_id: device.id
                 })
               )

      assert [_descriptor] = Plugins.list_runtime_descriptors(workspace.id, user.id, device.id)

      activation = Repo.get!(PluginActivation, consent.activation_id)

      capability_grant_id =
        RuntimeDescriptors.capability_grant_id(
          application,
          bundle,
          activation,
          consent,
          user.id,
          device.id
        )

      frame_generation =
        current_frame_generation!(
          application,
          bundle,
          activation,
          consent,
          user.id,
          device.id,
          capability_grant_id
        )

      storage_context = %{
        application_id: application.id,
        plugin_id: application.plugin_id,
        workspace_id: workspace.id,
        surface: "workspace",
        operation: "write",
        user_id: user.id,
        device_id: device.id,
        state_head_hash: application.state_head_hash,
        consent_head_hash: consent.event_hash,
        capability_grant_id: capability_grant_id,
        consent_epoch: consent.consent_epoch,
        frame_generation: frame_generation
      }

      assert {:ok, _payload} =
               Plugins.runtime_bundle_with_pins(
                 application.id,
                 workspace.id,
                 user.id,
                 device.id,
                 application.state_head_hash,
                 consent.event_hash
               )

      assert {:ok, _context} = Plugins.authorize_storage_context(storage_context)

      PluginActivation
      |> Repo.get!(consent.activation_id)
      |> PluginActivation.changeset(%{enabled: false})
      |> Repo.update!()

      assert [] = Plugins.list_runtime_descriptors(workspace.id, user.id, device.id)

      assert {:error, :plugin_activation_disabled} =
               Plugins.runtime_bundle_with_pins(
                 application.id,
                 workspace.id,
                 user.id,
                 device.id,
                 application.state_head_hash,
                 consent.event_hash
               )

      assert {:error, :forbidden, "plugin_storage_consent_invalid"} =
               Plugins.authorize_storage_context(storage_context)
    end

    test "rejects bundle promotion when the approver is not a workspace admin or owner" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
          "main.js" => "export default {}"
        })

      assert {:ok, %PluginBundleCandidate{} = candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 application_id: application.id,
                 workspace_id: workspace.id,
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      other_user =
        Repo.insert!(%User{
          email: "plugin-approver-#{System.unique_integer([:positive])}@example.com",
          name: "Other User",
          account_type: "registered"
        })

      approval =
        approval_attrs(candidate, %{
          approver_user_id: other_user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:error, :plugin_bundle_approval_forbidden} =
               Plugins.promote_bundle_candidate(candidate, approval)
    end

    test "rejects bundle promotion from an editor with document share management authority" do
      %{user: owner, workspace: workspace, device: owner_device} = account_context()
      editor = insert_user!()
      editor_device = insert_signing_device!(editor, "Editor Device")
      editor_role = workspace_role!(workspace.id, "editor")

      append_workspace_member_authority!(workspace.id, editor.id, editor_role)

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.editor-approval",
          created_by_user_id: owner.id,
          state_head_hash: "state-head"
        })

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.editor-approval","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default {}"
        })

      assert {:ok, candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 application_id: application.id,
                 workspace_id: workspace.id,
                 created_by_user_id: owner.id,
                 created_by_device_id: owner_device.id
               })

      approval =
        approval_attrs(candidate, %{
          approver_user_id: editor.id,
          approver_device_id: editor_device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:error, :plugin_bundle_approval_forbidden} =
               Plugins.promote_bundle_candidate(candidate, approval)
    end

    test "rejects candidate archives with runtime dependencies or unsafe remote sources" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
          "main.js" => "import x from 'https://example.com/x.js';"
        })

      assert {:error, :plugin_archive_runtime_dependency} =
               Plugins.create_local_bundle_candidate(archive_path, attrs)

      assert Repo.get_by(AuditEvent, type: "plugin.artifact.validation_failed")

      assert {:error, :plugin_archive_runtime_dependency} =
               plugin_archive_path(%{
                 "manifest.json" =>
                   ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
                 "main.js" => "URL.createObjectURL(new Blob([]));"
               })
               |> Plugins.create_local_bundle_candidate(attrs)

      for forbidden_source <- [
            "import/*blocked*/('https://example.com/x.js');",
            "import 'https://example.com/x.js';",
            "new/**/Worker('worker.js');",
            "new /*blocked*/ SharedWorker('worker.js');",
            "navigator['serviceWorker'].register('/sw.js');",
            "URL['createObjectURL'](new Blob([]));",
            "navigator['service' + 'Worker'].register('/sw.js');",
            "navigator['serv' + 'ice' + 'Worker'].register('/sw.js');",
            "globalThis['import' + 'Scripts']('dep.js');",
            "globalThis['im' + 'port' + 'Scripts']('dep.js');",
            "navigator[`serviceWorker`].register('/sw.js');",
            "globalThis[`importScripts`]('dep.js');",
            "new globalThis['Worker']('worker.js');",
            "new (globalThis['Worker'])('worker.js');",
            "new globalThis[`Worker`]('worker.js');",
            "new window['Shared' + 'Worker']('worker.js');",
            "new (window['Shared' + 'Worker'])('worker.js');",
            "new self['Bl' + 'ob'](['export {}']);",
            "new (self['Bl' + 'ob'])(['export {}']);",
            "new self[`Blob`](['export {}']);",
            "URL['create' + 'ObjectURL'](new Blob([]));",
            "globalThis['URL']['create' + 'ObjectURL'](new Blob([]));",
            "(globalThis['URL'])['create' + 'ObjectURL'](new Blob([]));",
            "URL[`createObjectURL`](new Blob([]));",
            "globalThis[`URL`][`createObjectURL`](new Blob([]));"
          ] do
        assert {:error, :plugin_archive_runtime_dependency} =
                 plugin_archive_path(%{
                   "manifest.json" =>
                     ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
                   "main.js" => forbidden_source
                 })
                 |> Plugins.create_local_bundle_candidate(attrs)
      end

      for forbidden_source <- [
            "globalThis.getApp?.();",
            "globalThis.addSidebarPanel?.();"
          ] do
        assert {:error, :plugin_archive_runtime_dependency} =
                 plugin_archive_path(%{
                   "manifest.json" =>
                     ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
                   "main.js" => forbidden_source
                 })
                 |> Plugins.create_local_bundle_candidate(attrs)
      end

      for forbidden_source <- [
            "globalThis['get' + 'App']?.();",
            "window['workspace' + 'Manager'];",
            "self['Workspace' + 'Leaf'];",
            "globalThis['render' + 'Plugin' + 'Content'];",
            "globalThis['register' + 'Dom' + 'Event'];",
            "globalThis['add' + 'Sidebar' + 'Panel']?.();"
          ] do
        assert {:error, :plugin_archive_runtime_dependency} =
                 plugin_archive_path(%{
                   "manifest.json" =>
                     ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
                   "main.js" => forbidden_source
                 })
                 |> Plugins.create_local_bundle_candidate(attrs)
      end

      assert {:ok, _candidate} =
               plugin_archive_path(%{
                 "manifest.json" =>
                   ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
                 "main.js" => "export const value = \"</script><!-- -->\";"
               })
               |> Plugins.create_local_bundle_candidate(attrs)

      assert {:ok, _candidate} =
               plugin_archive_path(%{
                 "manifest.json" =>
                   ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
                 "main.js" => "export const message = \"theme import is detected\";"
               })
               |> Plugins.create_local_bundle_candidate(attrs)

      assert {:error, :plugin_archive_inline_source_unsafe} =
               plugin_archive_path(%{
                 "manifest.json" =>
                   ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
                 "main.js" => "export default {};",
                 "styles.css" => "/* </style> */"
               })
               |> Plugins.create_local_bundle_candidate(attrs)

      assert {:error, :plugin_archive_inline_source_unsafe} =
               plugin_archive_path(%{
                 "manifest.json" =>
                   ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
                 "main.js" => "export default {};",
                 "styles.css" => "/* </StYlE> */"
               })
               |> Plugins.create_local_bundle_candidate(attrs)

      requested_audit_before = fetch_audit_hosts("plugin.artifact.fetch_requested")
      failed_audit_before = fetch_audit_hosts("plugin.artifact.fetch_failed")

      assert {:error, :plugin_source_private_target} =
               Plugins.create_remote_bundle_candidate("https://127.0.0.1/a.zip", attrs)

      assert {:error, :plugin_source_private_target} =
               Plugins.create_remote_bundle_candidate("https://localhost/a.zip", attrs)

      assert ["127.0.0.1", "localhost"] =
               fetch_audit_hosts("plugin.artifact.fetch_requested")
               |> Enum.drop(length(requested_audit_before))

      assert ["127.0.0.1", "localhost"] =
               fetch_audit_hosts("plugin.artifact.fetch_failed")
               |> Enum.drop(length(failed_audit_before))

      for unsafe_source_url <- [
            "https://plugins.example.com/plugin.zip\r\nX-Injected: yes",
            "https://plugins.example.com/plugin.zip?download=1\r\nX-Injected: yes"
          ] do
        assert {:error, :plugin_source_invalid} =
                 Plugins.create_remote_bundle_candidate(unsafe_source_url, attrs)
      end

      assert length(requested_audit_before) + 4 ==
               length(fetch_audit_hosts("plugin.artifact.fetch_requested"))

      assert length(failed_audit_before) + 4 ==
               length(fetch_audit_hosts("plugin.artifact.fetch_failed"))
    end

    test "validates manifest network endpoints before candidate admission" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.network-endpoints",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      valid_endpoint = %{
        "id" => "api",
        "url" => "https://api.example.com/export",
        "methods" => ["POST"],
        "routes" => ["proxy"],
        "allowedHeaders" => ["accept", "content-type"],
        "bodySchema" => "json",
        "credentialAudience" => "api.example.com",
        "maxRequestBytes" => 1024,
        "maxResponseBytes" => 2048
      }

      invalid_endpoints = [
        %{valid_endpoint | "url" => "http://api.example.com/export"},
        %{valid_endpoint | "url" => "https://user:pass@api.example.com/export"},
        %{valid_endpoint | "url" => "https://api.example.com/export#frag"},
        %{valid_endpoint | "url" => "https://api.example.com:443/export"},
        %{valid_endpoint | "url" => "https://api.example.com/a/../b"},
        %{valid_endpoint | "url" => "https://api.example.com/%2Fsecret"},
        %{valid_endpoint | "url" => "https://localhost/export"},
        %{valid_endpoint | "url" => "https://127.0.0.1/export"},
        %{valid_endpoint | "url" => "https://metadata/export"},
        %{valid_endpoint | "methods" => ["post"]},
        %{valid_endpoint | "methods" => []},
        %{valid_endpoint | "routes" => ["direct"]},
        %{valid_endpoint | "routes" => ["auto"]},
        %{valid_endpoint | "routes" => ["extension"]},
        %{valid_endpoint | "routes" => ["browser"]},
        %{valid_endpoint | "routes" => []},
        %{valid_endpoint | "allowedHeaders" => ["authorization"]},
        %{valid_endpoint | "allowedHeaders" => ["X-Token"]},
        %{valid_endpoint | "bodySchema" => "form"},
        Map.put(valid_endpoint, "proxy_url", "https://proxy.example.com/"),
        Map.put(valid_endpoint, "mode", "no-cors")
      ]

      for endpoint <- invalid_endpoints do
        assert {:error, :plugin_manifest_invalid_network_endpoint} =
                 plugin_archive_path(%{
                   "manifest.json" => Jason.encode!(network_endpoint_manifest([endpoint])),
                   "main.js" => "export default {};"
                 })
                 |> Plugins.create_local_bundle_candidate(attrs)
      end

      assert {:ok, candidate} =
               plugin_archive_path(%{
                 "manifest.json" => Jason.encode!(network_endpoint_manifest([valid_endpoint])),
                 "main.js" => "export default {};"
               })
               |> Plugins.create_local_bundle_candidate(attrs)

      assert candidate.validation_status == "valid"
      assert candidate.endpoint_hash == semantic_hash([valid_endpoint])
    end

    test "does not expose remote candidate creation from a local archive path" do
      refute function_exported?(Plugins, :create_remote_bundle_candidate, 3)
      refute function_exported?(Plugins, :create_bundle_candidate_from_archive_path, 4)
    end

    test "rejects link-local, mapped private, and shared-range remote candidate targets" do
      for address <- [
            {0xFE80, 0, 0, 0, 0, 0, 0, 1},
            {0xFE81, 0, 0, 0, 0, 0, 0, 1},
            {0xFEBF, 0, 0, 0, 0, 0, 0, 1},
            {0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001},
            {0, 0, 0, 0, 0, 0xFFFF, 0x6464, 0x64C8},
            {100, 64, 0, 1},
            {100, 127, 255, 254}
          ] do
        assert {:error, :plugin_source_private_target} =
                 Artifact.verified_remote_source_target(
                   "https://plugins.example.com/plugin.zip",
                   fn "plugins.example.com" -> {:ok, [address]} end
                 )
      end

      assert {:error, :plugin_source_private_target} =
               Artifact.verified_remote_source_target(
                 "https://plugins.example.com/plugin.zip",
                 fn "plugins.example.com" -> {:ok, [{100, 100, 100, 200}]} end
               )

      assert {:error, :plugin_source_private_target} =
               Artifact.verified_remote_source_target(
                 "https://metadata/plugin.zip",
                 fn "metadata" -> {:ok, [{203, 0, 113, 10}]} end
               )

      assert {:ok, %{address: {0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888}}} =
               Artifact.verified_remote_source_target(
                 "https://plugins.example.com/plugin.zip",
                 fn "plugins.example.com" ->
                   {:ok, [{0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888}]}
                 end
               )
    end

    test "rejects mixed private and public remote candidate DNS answers" do
      for addresses <- [
            [{127, 0, 0, 1}, {203, 0, 113, 10}],
            [{203, 0, 113, 10}, {100, 64, 0, 1}],
            [{0xFE80, 0, 0, 0, 0, 0, 0, 1}, {0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888}]
          ] do
        assert {:error, :plugin_source_private_target} =
                 Artifact.verified_remote_source_target(
                   "https://plugins.example.com/plugin.zip",
                   fn "plugins.example.com" -> {:ok, addresses} end
                 )
      end
    end

    test "rejects manifests that combine plaintext read with synced storage write" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      for permissions <- [
            ["document:read:active", "storage:write:workspace"],
            ["plaintext:render:block:mermaid", "storage:write:document"],
            ["editor:context:read", "storage:write:workspace"]
          ] do
        assert {:error, :plugin_manifest_dangerous_permission_combination} =
                 plugin_archive_path(%{
                   "manifest.json" => plugin_manifest_json(application.plugin_id, permissions),
                   "main.js" => "export default {}"
                 })
                 |> Plugins.create_local_bundle_candidate(attrs)
      end
    end

    test "rejects bundle candidates with invalid manifest permissions" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      for permissions <- [
            ["document:read"],
            ["storage:read"],
            ["storage:write:server"],
            ["plaintext:render:markdown"],
            ["plaintext:render:block:full-document"],
            ["ui:status"],
            ["ui:sidebar_panel"],
            ["ui:document_tree_action"],
            ["ui:document_tree_badge"],
            ["ui:document_tree_decoration"],
            ["ui:document_tree_virtual_section"],
            ["plugin:admin"],
            [""],
            [42]
          ] do
        assert {:error, :plugin_manifest_invalid_permission} =
                 plugin_archive_path(%{
                   "manifest.json" => plugin_manifest_json(application.plugin_id, permissions),
                   "main.js" => "export default {}"
                 })
                 |> Plugins.create_local_bundle_candidate(attrs)
      end
    end

    test "accepts bundle candidates with known manifest permission grammar" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      permissions = [
        "document:read:active",
        "document:write",
        "storage:read:userLocal",
        "storage:write:cache",
        "credential:use",
        "network:fetch",
        "editor:selection:read",
        "editor:context:read",
        "plaintext:render:block:mermaid",
        "plaintext:render:inline:code",
        "ui:command",
        "ui:sidebar",
        "ui:statusbar",
        "ui:document_tree:*",
        "ui:settings_iframe",
        "ui:settings_declarative",
        "ui:declarative_modal",
        "ui:menu_item",
        "ui:editor"
      ]

      assert {:ok, %PluginBundleCandidate{}} =
               plugin_archive_path(%{
                 "manifest.json" => plugin_manifest_json(application.plugin_id, permissions),
                 "main.js" => "export default {}"
               })
               |> Plugins.create_local_bundle_candidate(attrs)
    end

    test "rejects bundle candidates with forbidden renderer slots" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      for slot <- [
            %{"kind" => "block", "type" => "markdown"},
            %{"kind" => "block", "type" => "md"},
            %{"kind" => "inline", "type" => "badge"},
            %{"kind" => "inline", "type" => "document"},
            %{"kind" => "inline", "type" => "full-document"},
            %{"kind" => "block", "type" => "BadType"},
            %{"kind" => "full", "type" => "mermaid"},
            %{"kind" => "block", "type" => ""}
          ] do
        assert {:error, :plugin_manifest_invalid_renderer_slot} =
                 plugin_archive_path(%{
                   "manifest.json" => plugin_manifest_json(application.plugin_id, [], [slot]),
                   "main.js" => "export default {}"
                 })
                 |> Plugins.create_local_bundle_candidate(attrs)
      end
    end

    test "fetches remote candidates through the verified connection target" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
          "main.js" => "export default {}"
        })

      archive = File.read!(archive_path)

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      fetcher = fn target ->
        assert target.host == "plugins.example.com"
        assert target.address == {93, 184, 216, 34}
        {:ok, 200, [{"content-length", byte_size(archive)}], archive}
      end

      assert {:ok, %PluginBundleCandidate{} = candidate} =
               BundleCandidates.create_remote(
                 "https://plugins.example.com/plugin.zip",
                 attrs,
                 target_resolver: fn "https://plugins.example.com/plugin.zip" ->
                   {:ok,
                    %{
                      uri: URI.parse("https://plugins.example.com/plugin.zip"),
                      host: "plugins.example.com",
                      address: {93, 184, 216, 34}
                    }}
                 end,
                 fetcher: fetcher
               )

      assert candidate.source_kind == "remote_https_url"
      assert candidate.source_url == "https://plugins.example.com/plugin.zip"
    end

    test "manually verifies remote candidate redirect targets before fetching redirected bytes" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
          "main.js" => "export default {}"
        })

      archive = File.read!(archive_path)

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      target_for = fn url, address ->
        uri = URI.parse(url)
        {:ok, %{uri: uri, host: uri.host, address: address}}
      end

      fetcher = fn
        %{uri: %{path: "/plugin.zip"}, host: "plugins.example.com"} ->
          {:ok, 302, [{"Location", "/download/plugin.zip"}], ""}

        %{uri: %{path: "/download/plugin.zip"}, host: "plugins.example.com"} ->
          {:ok, 200, [{"content-length", byte_size(archive)}], archive}
      end

      assert {:ok, %PluginBundleCandidate{} = candidate} =
               BundleCandidates.create_remote(
                 "https://plugins.example.com/plugin.zip",
                 attrs,
                 target_resolver: fn
                   "https://plugins.example.com/plugin.zip" ->
                     target_for.("https://plugins.example.com/plugin.zip", {93, 184, 216, 34})

                   "https://plugins.example.com/download/plugin.zip" ->
                     target_for.(
                       "https://plugins.example.com/download/plugin.zip",
                       {93, 184, 216, 34}
                     )
                 end,
                 fetcher: fetcher
               )

      assert candidate.source_url == "https://plugins.example.com/plugin.zip"

      assert ["plugins.example.com", "plugins.example.com"] =
               fetch_audit_hosts("plugin.artifact.fetch_requested")

      assert ["plugins.example.com", "plugins.example.com"] =
               fetch_audit_hosts("plugin.artifact.fetch_completed")
    end

    test "rejects remote candidate redirects to private targets before the redirected request" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      assert {:error, :plugin_source_private_target} =
               BundleCandidates.create_remote(
                 "https://plugins.example.com/plugin.zip",
                 attrs,
                 target_resolver: fn
                   "https://plugins.example.com/plugin.zip" ->
                     {:ok,
                      %{
                        uri: URI.parse("https://plugins.example.com/plugin.zip"),
                        host: "plugins.example.com",
                        address: {93, 184, 216, 34}
                      }}

                   "https://carrier.example.com/plugin.zip" ->
                     Artifact.verified_remote_source_target(
                       "https://carrier.example.com/plugin.zip",
                       fn "carrier.example.com" -> {:ok, [{100, 64, 0, 1}]} end
                     )
                 end,
                 fetcher: fn
                   %{host: "plugins.example.com"} ->
                     {:ok, 302, [{"Location", "https://carrier.example.com/plugin.zip"}], ""}

                   redirected ->
                     flunk("unexpected redirected fetch: #{inspect(redirected)}")
                 end
               )

      assert ["carrier.example.com"] = fetch_audit_hosts("plugin.artifact.fetch_failed")
    end

    test "fails closed when redirect target audit cannot be recorded" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      fetch_count = :counters.new(1, [])
      audit_error = invalid_audit_changeset()

      assert {:error, ^audit_error} =
               BundleCandidates.create_remote(
                 "https://plugins.example.com/plugin.zip",
                 attrs,
                 target_resolver: fn url ->
                   uri = URI.parse(url)
                   {:ok, %{uri: uri, host: uri.host, address: {93, 184, 216, 34}}}
                 end,
                 fetcher: fn target ->
                   :counters.add(fetch_count, 1, 1)

                   case target.host do
                     "plugins.example.com" ->
                       {:ok, 302, [{"Location", "https://cdn.example.com/plugin.zip"}], ""}

                     "cdn.example.com" ->
                       flunk("redirect target was fetched without required audit")
                   end
                 end,
                 record_fetch_requested: fn
                   %{source_url: "https://cdn.example.com/plugin.zip"} ->
                     {:error, audit_error}

                   _attrs ->
                     {:ok, %{}}
                 end
               )

      assert :counters.get(fetch_count, 1) == 1
    end

    test "rejects remote candidate redirect chains over the hop limit" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      assert {:error, :plugin_source_redirect_limit_exceeded} =
               BundleCandidates.create_remote(
                 "https://plugins.example.com/plugin.zip",
                 attrs,
                 target_resolver: fn url ->
                   uri = URI.parse(url)
                   {:ok, %{uri: uri, host: uri.host, address: {93, 184, 216, 34}}}
                 end,
                 fetcher: fn %{uri: uri} ->
                   step = uri.query || "step=0"
                   {current, ""} = step |> String.replace_prefix("step=", "") |> Integer.parse()
                   {:ok, 302, [{"Location", "/plugin.zip?step=#{current + 1}"}], ""}
                 end
               )
    end

    test "rejects remote response bodies over the acquisition limit before writing candidates" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      assert {:error, :plugin_source_response_too_large} =
               BundleCandidates.create_remote(
                 "https://plugins.example.com/plugin.zip",
                 attrs,
                 target_resolver: fn _url ->
                   {:ok,
                    %{
                      uri: URI.parse("https://plugins.example.com/plugin.zip"),
                      host: "plugins.example.com",
                      address: {93, 184, 216, 34}
                    }}
                 end,
                 fetcher: fn _target ->
                   {:ok, 200, [{"content-length", 5_000_001}], ""}
                 end
               )
    end

    test "fails closed when required artifact failure audit cannot be recorded" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      audit_error = invalid_audit_changeset()

      assert {:error, ^audit_error} =
               BundleCandidates.create_remote(
                 "https://plugins.example.com/plugin.zip",
                 attrs,
                 target_resolver: fn _url ->
                   {:ok,
                    %{
                      uri: URI.parse("https://plugins.example.com/plugin.zip"),
                      host: "plugins.example.com",
                      address: {93, 184, 216, 34}
                    }}
                 end,
                 fetcher: fn _target -> {:error, :plugin_source_fetch_failed} end,
                 record_fetch_failed: fn _attrs, :plugin_source_fetch_failed ->
                   {:error, audit_error}
                 end
               )

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
          "main.js" => "import x from 'https://example.com/x.js';"
        })

      assert {:error, %Ecto.Changeset{} = changeset} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 attrs
                 | created_by_user_id: %{"plaintext" => "audit insert must fail"}
               })

      refute changeset.valid?
    end

    test "rejects candidate archives with unsafe paths, unknown files, or missing required files" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      assert {:error, :plugin_archive_path_invalid} =
               plugin_archive_path(%{
                 "manifest.json" =>
                   ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
                 "nested\\extra.js" => "export default {}",
                 "main.js" => "export default {}"
               })
               |> Plugins.create_local_bundle_candidate(attrs)

      assert {:error, :plugin_archive_path_invalid} =
               plugin_archive_path(%{
                 "manifest.json" =>
                   ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0","resources":[{"path":"resources/./data.json","kind":"json","media_type":"application/json"}]}),
                 "main.js" => "export default {}",
                 "resources/./data.json" => ~s({"ok":true})
               })
               |> Plugins.create_local_bundle_candidate(attrs)

      assert {:error, :plugin_archive_path_invalid} =
               plugin_archive_path(%{
                 "manifest.json" =>
                   ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0","resources":[{"path":"resources/data\\t.json","kind":"json","media_type":"application/json"}]}),
                 "main.js" => "export default {}",
                 "resources/data\t.json" => ~s({"ok":true})
               })
               |> Plugins.create_local_bundle_candidate(attrs)

      assert {:error, :plugin_manifest_invalid_resource} =
               plugin_archive_path(%{
                 "manifest.json" =>
                   ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0","resources":[{"path":"resources/./data.json","kind":"json","media_type":"application/json"}]}),
                 "main.js" => "export default {}",
                 "resources/data.json" => ~s({"ok":true})
               })
               |> Plugins.create_local_bundle_candidate(attrs)

      manifest_with_nul_resource =
        Jason.encode!(%{
          "scope" => %{
            "supportedOwnerScopes" => ["workspace"],
            "defaultOwnerScope" => "workspace",
            "workspaceApplication" => "required"
          },
          "id" => "com.example.notes",
          "version" => "1.0.0",
          "resources" => [
            %{
              "path" => "resources/data" <> <<0>> <> ".json",
              "kind" => "json",
              "media_type" => "application/json"
            }
          ]
        })

      assert {:error, :plugin_manifest_invalid_resource} =
               plugin_archive_path(%{
                 "manifest.json" => manifest_with_nul_resource,
                 "main.js" => "export default {}",
                 "resources/data.json" => ~s({"ok":true})
               })
               |> Plugins.create_local_bundle_candidate(attrs)

      assert {:error, :plugin_manifest_invalid_resource} =
               plugin_archive_path(%{
                 "manifest.json" =>
                   ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0","resources":{"path":"resources/data.json","kind":"json","media_type":"application/json"}}),
                 "main.js" => "export default {}"
               })
               |> Plugins.create_local_bundle_candidate(attrs)

      assert {:error, :plugin_manifest_invalid_resource} =
               plugin_archive_path(%{
                 "manifest.json" =>
                   ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0","resources":[{"path":"resources/data.json","media_type":"application/json"}]}),
                 "main.js" => "export default {}"
               })
               |> Plugins.create_local_bundle_candidate(attrs)

      assert {:error, :plugin_archive_unknown_file} =
               plugin_archive_path(%{
                 "manifest.json" =>
                   ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
                 "main.js" => "export default {}",
                 "chunk.js" => "export default {}"
               })
               |> Plugins.create_local_bundle_candidate(attrs)

      assert {:error, :plugin_archive_required_file_missing} =
               plugin_archive_path(%{
                 "manifest.json" =>
                   ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"})
               })
               |> Plugins.create_local_bundle_candidate(attrs)
    end

    test "rejects package entry resource logical paths with control characters" do
      %{user: user} = account_context()
      entry_id = Ecto.UUID.generate()

      changeset =
        PluginPackageEntry.changeset(%PluginPackageEntry{id: entry_id}, %{
          owner_scope_kind: "user",
          owner_user_id: user.id,
          entry_kind: "resource",
          logical_path: "resources/data\t.json",
          resource_kind: "json",
          media_type: "application/json",
          byte_length: 2,
          hash: hash("{}"),
          storage_path: "plugin-packages/#{entry_id}",
          status: "candidate"
        })

      assert %{logical_path: ["must be a canonical resource path"]} = errors_on(changeset)
    end

    test "rejects package entry storage paths that do not match the entry id" do
      %{user: user} = account_context()
      entry_id = Ecto.UUID.generate()

      changeset =
        PluginPackageEntry.changeset(%PluginPackageEntry{id: entry_id}, %{
          owner_scope_kind: "user",
          owner_user_id: user.id,
          entry_kind: "resource",
          logical_path: "resources/data.json",
          resource_kind: "json",
          media_type: "application/json",
          byte_length: 2,
          hash: hash("{}"),
          storage_path: "plugin-packages/#{Ecto.UUID.generate()}",
          status: "candidate"
        })

      assert %{storage_path: ["must match package entry object key"]} = errors_on(changeset)
    end

    test "database rejects package entry kind and logical path mismatches" do
      %{user: user} = account_context()

      assert_package_entry_db_rejects(
        package_entry_db_attrs(
          %{owner_scope_kind: "user", owner_user_id: user.id},
          %{
            entry_kind: "manifest",
            logical_path: "resources/not-manifest.json",
            resource_kind: nil,
            media_type: "application/json"
          }
        )
      )

      assert_package_entry_db_rejects(
        package_entry_db_attrs(
          %{owner_scope_kind: "user", owner_user_id: user.id},
          %{
            entry_kind: "resource",
            logical_path: "main.js",
            resource_kind: "text",
            media_type: "text/javascript"
          }
        )
      )

      assert_package_entry_db_rejects(
        package_entry_db_attrs(
          %{owner_scope_kind: "user", owner_user_id: user.id},
          %{storage_path: "plugin-packages/#{Ecto.UUID.generate()}"}
        )
      )
    end

    test "database rejects duplicate package entry singleton kinds" do
      %{user: user, workspace: workspace, device: device} = account_context()

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.entry-shape","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"rendererSlots":[],"documentScopes":[]}),
          "main.js" => "export default {}"
        })

      assert {:ok, candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 workspace_id: workspace.id,
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      assert_package_entry_db_rejects(
        package_entry_db_attrs(
          %{owner_scope_kind: "workspace", owner_workspace_id: workspace.id},
          %{
            candidate_id: candidate.id,
            entry_kind: "main_js",
            logical_path: "main.js",
            resource_kind: nil,
            media_type: "text/javascript"
          }
        )
      )

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)
      bundle = Repo.get!(PluginBundle, package.current_bundle_id)

      assert_package_entry_db_rejects(
        package_entry_db_attrs(
          %{owner_scope_kind: "workspace", owner_workspace_id: workspace.id},
          %{
            candidate_id: candidate.id,
            bundle_id: bundle.id,
            package_id: package.id,
            entry_kind: "manifest",
            logical_path: "manifest.json",
            resource_kind: nil,
            media_type: "application/json",
            status: "pinned",
            pinned_at: DateTime.utc_now()
          }
        )
      )
    end

    test "rejects oversized decompressed candidate archives before extraction" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.notes",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      attrs = %{
        application_id: application.id,
        workspace_id: workspace.id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      }

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.notes","version":"1.0.0"}),
          "main.js" => String.duplicate("a", 5_000_001)
        })

      assert {:error, :plugin_archive_decompressed_too_large} =
               Plugins.create_local_bundle_candidate(archive_path, attrs)
    end
  end

  describe "encrypted plugin storage" do
    test "requires encrypted bytes, nonce, key version, and scoped AAD inputs" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.storage",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      {:ok, activation} =
        Plugins.create_activation(%{
          application_id: application.id,
          user_id: user.id,
          device_id: device.id,
          activation_scope_kind: "device",
          enabled: true
        })

      attrs = %{
        application_id: application.id,
        package_id: application.package_id,
        workspace_id: workspace.id,
        plugin_id: "com.example.storage",
        activation_id: activation.id,
        scope: :document,
        scope_id: "00000000-0000-4000-8000-000000000010",
        key: "index",
        ciphertext: <<1, 2, 3>>,
        nonce: <<4, 5, 6>>,
        key_version: 7
      }

      assert {:ok, %PluginKV{} = entry} = Plugins.put_kv(attrs)
      assert entry.ciphertext == <<1, 2, 3>>

      second_device = insert_signing_device!(user, "Second Device")

      {:ok, second_activation} =
        Plugins.create_activation(%{
          application_id: application.id,
          user_id: user.id,
          device_id: second_device.id,
          activation_scope_kind: "device",
          enabled: true
        })

      assert {:ok, %PluginKV{} = updated_entry} =
               Plugins.put_kv(%{attrs | activation_id: second_activation.id, ciphertext: <<9>>})

      assert updated_entry.activation_id == second_activation.id
      assert updated_entry.ciphertext == <<9>>

      assert Plugins.get_kv(application.id, :document, attrs.scope_id, "index").ciphertext ==
               <<9>>

      assert Plugins.storage_aad(attrs) == %{
               "protocol" => "refmd",
               "version" => 1,
               "purpose" => "plugin_data",
               "plugin_id" => "com.example.storage",
               "package_id" => application.package_id,
               "application_id" => application.id,
               "activation_id" => attrs.activation_id,
               "workspace_id" => workspace.id,
               "scope" => "document",
               "scope_id" => "00000000-0000-4000-8000-000000000010",
               "key" => "index"
             }

      record_attrs =
        attrs
        |> Map.drop([:key, :ciphertext])
        |> Map.merge(%{
          id: "10000000-0000-4000-8000-000000000001",
          kind: "annotation",
          encrypted_data: <<7, 8, 9>>
        })

      assert {:ok, %PluginRecord{} = record} = Plugins.put_record(record_attrs)
      assert record.kind == "annotation"
      assert record.encrypted_data == <<7, 8, 9>>

      assert %PluginRecord{id: record_id, encrypted_data: <<7, 8, 9>>} =
               Plugins.get_record(
                 record.id,
                 application.id,
                 :document,
                 attrs.scope_id
               )

      assert record_id == record.id

      assert {:error, changeset} = Plugins.put_record(%{record_attrs | encrypted_data: nil})
      assert %{encrypted_data: ["can't be blank"]} = errors_on(changeset)

      assert {:error, changeset} = Plugins.put_record(%{record_attrs | scope: :user})
      assert %{scope: ["is invalid"]} = errors_on(changeset)

      assert {:ok, %PluginKV{}} =
               Plugins.delete_kv(
                 application.id,
                 :document,
                 attrs.scope_id,
                 "index"
               )

      assert Plugins.get_kv(
               application.id,
               :document,
               attrs.scope_id,
               "index"
             ) == nil

      assert {:error, :not_found} =
               Plugins.delete_kv(
                 application.id,
                 :document,
                 attrs.scope_id,
                 "index"
               )

      assert {:ok, %PluginRecord{}} =
               Plugins.delete_record(
                 record.id,
                 application.id,
                 :document,
                 attrs.scope_id
               )

      assert Plugins.get_record(
               record.id,
               application.id,
               :document,
               attrs.scope_id
             ) == nil
    end

    test "rejects storage writes for a different plugin or workspace" do
      %{user: user, workspace: workspace} = account_context()
      other_workspace = create_workspace(user)

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.storage",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      assert {:error, :bundle_application_mismatch} =
               Plugins.put_kv(%{
                 application_id: application.id,
                 package_id: application.package_id,
                 workspace_id: other_workspace.id,
                 plugin_id: "com.example.storage",
                 activation_id: Ecto.UUID.generate(),
                 scope: :workspace,
                 scope_id: other_workspace.id,
                 key: "index",
                 ciphertext: <<1>>,
                 nonce: <<2>>,
                 key_version: 1
               })
    end

    test "activation deletion preserves application-scoped server storage" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.activation-storage",
          created_by_user_id: user.id
        })

      {:ok, activation} =
        Plugins.create_activation(%{
          application_id: application.id,
          user_id: user.id,
          device_id: device.id,
          activation_scope_kind: "device",
          enabled: true
        })

      attrs = %{
        application_id: application.id,
        package_id: application.package_id,
        workspace_id: workspace.id,
        plugin_id: application.plugin_id,
        activation_id: activation.id,
        scope: :workspace,
        scope_id: workspace.id,
        key: "shared-index",
        ciphertext: <<1, 2, 3>>,
        nonce: <<4, 5, 6>>,
        key_version: 1
      }

      assert {:ok, %PluginKV{} = kv_entry} = Plugins.put_kv(attrs)

      record_attrs =
        attrs
        |> Map.drop([:key, :ciphertext])
        |> Map.merge(%{
          id: "10000000-0000-4000-8000-000000000060",
          kind: "shared-record",
          encrypted_data: <<7, 8, 9>>
        })

      assert {:ok, %PluginRecord{} = record} = Plugins.put_record(record_attrs)

      assert {:ok, deleted_activation} =
               Plugins.delete_activation(activation, actor_device_id: device.id)

      assert deleted_activation.deleted_at
      assert Repo.get(PluginKV, kv_entry.id)
      assert Repo.get(PluginRecord, record.id)
    end
  end

  describe "plugin consent events" do
    test "appends allow, deny, and revoke decisions as a rollback-checked chain" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.consent",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      %{bundle: bundle} = pin_bundle!(application, user, device)

      base =
        consent_attrs(%{
          application_id: application.id,
          workspace_id: workspace.id,
          plugin_id: "com.example.consent",
          version: bundle.version,
          bundle_hash: bundle.bundle_hash,
          manifest_hash: bundle.manifest_hash,
          permissions_hash: bundle.permissions_hash,
          endpoint_hash: bundle.endpoint_hash,
          document_scope_hash: bundle.document_scope_hash,
          user_id: user.id,
          device_id: device.id,
          signer_user_id: user.id,
          signer_device_id: device.id
        })

      stale_head = hash("old-head")

      assert {:error, :invalid_consent_genesis} =
               Plugins.append_consent_event(
                 base
                 |> Map.delete(:hybrid_signature)
                 |> Map.put(:previous_event_hash, stale_head)
                 |> consent_attrs()
               )

      assert {:ok, %PluginConsentEvent{} = allow} = Plugins.append_consent_event(base)
      assert allow.decision == "allow"
      allow_event_hash = allow.event_hash

      assert {:error, :plugin_consent_head_pin_required} =
               Plugins.allowed_consent_with_pin(application.id, user.id, device.id, nil)

      assert {:error, :plugin_consent_rollback} =
               Plugins.allowed_consent_with_pin(application.id, user.id, device.id, stale_head)

      assert {:ok, ^allow} =
               Plugins.allowed_consent_with_pin(
                 application.id,
                 user.id,
                 device.id,
                 allow_event_hash
               )

      assert {:error, :stale_consent_head} =
               Plugins.append_consent_event(
                 base
                 |> Map.delete(:hybrid_signature)
                 |> Map.merge(%{
                   consent_epoch: 2,
                   previous_event_hash: stale_head,
                   decision: "deny"
                 })
                 |> consent_attrs()
               )

      assert {:ok, deny} =
               Plugins.append_consent_event(
                 base
                 |> Map.delete(:hybrid_signature)
                 |> Map.merge(%{
                   consent_epoch: 2,
                   previous_event_hash: allow_event_hash,
                   decision: "deny"
                 })
                 |> consent_attrs()
               )

      assert deny.decision == "deny"
      deny_event_hash = deny.event_hash

      assert {:error, :plugin_consent_not_allowed} =
               Plugins.allowed_consent_with_pin(
                 application.id,
                 user.id,
                 device.id,
                 deny_event_hash
               )

      assert Repo.get_by(AuditEvent, type: "plugin.consent.allowed")
      assert Repo.get_by(AuditEvent, type: "plugin.consent.denied")

      assert {:ok, revoke} =
               Plugins.append_consent_event(
                 base
                 |> Map.delete(:hybrid_signature)
                 |> Map.merge(%{
                   consent_epoch: 3,
                   previous_event_hash: deny_event_hash,
                   decision: "revoke"
                 })
                 |> consent_attrs()
               )

      assert revoke.decision == "revoke"
      assert Repo.get_by(AuditEvent, type: "plugin.consent.revoked")

      assert revoke_notification =
               Repo.get_by(Notification,
                 type: "plugin.runtime_revoked",
                 recipient_kind: "device",
                 recipient_id: device.id
               )

      assert revoke_notification.action_ref["workspace_id"] == workspace.id
      assert revoke_notification.action_ref["package_id"] == application.package_id
      assert revoke_notification.action_ref["application_id"] == application.id
      assert revoke_notification.action_ref["activation_id"] == revoke.activation_id
      assert revoke_notification.action_ref["plugin_id"] == application.plugin_id
      assert revoke_notification.action_ref["bundle_hash"] == bundle.bundle_hash
    end

    test "does not resurface current deny and revoke decisions as consent required" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, denied_application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.denied-consent",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      %{bundle: denied_bundle} = pin_bundle!(denied_application, user, device)

      denied_base =
        consent_attrs(%{
          application_id: denied_application.id,
          workspace_id: workspace.id,
          plugin_id: denied_application.plugin_id,
          version: denied_bundle.version,
          bundle_hash: denied_bundle.bundle_hash,
          manifest_hash: denied_bundle.manifest_hash,
          permissions_hash: denied_bundle.permissions_hash,
          endpoint_hash: denied_bundle.endpoint_hash,
          document_scope_hash: denied_bundle.document_scope_hash,
          user_id: user.id,
          device_id: device.id,
          signer_user_id: user.id,
          signer_device_id: device.id,
          decision: "deny"
        })

      assert {:ok, deny} = Plugins.append_consent_event(denied_base)
      assert deny.decision == "deny"
      assert [] = Plugins.list_runtime_descriptors(workspace.id, user.id, device.id)
      assert [] = Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)

      {:ok, revoked_application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.revoked-consent",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      %{bundle: revoked_bundle} = pin_bundle!(revoked_application, user, device)

      revoked_base =
        consent_attrs(%{
          application_id: revoked_application.id,
          workspace_id: workspace.id,
          plugin_id: revoked_application.plugin_id,
          version: revoked_bundle.version,
          bundle_hash: revoked_bundle.bundle_hash,
          manifest_hash: revoked_bundle.manifest_hash,
          permissions_hash: revoked_bundle.permissions_hash,
          endpoint_hash: revoked_bundle.endpoint_hash,
          document_scope_hash: revoked_bundle.document_scope_hash,
          user_id: user.id,
          device_id: device.id,
          signer_user_id: user.id,
          signer_device_id: device.id,
          decision: "deny"
        })

      assert {:ok, revoke_base} = Plugins.append_consent_event(revoked_base)

      assert {:ok, revoke} =
               Plugins.append_consent_event(
                 revoked_base
                 |> Map.delete(:hybrid_signature)
                 |> Map.merge(%{
                   consent_epoch: 2,
                   previous_event_hash: revoke_base.event_hash,
                   decision: "revoke"
                 })
                 |> consent_attrs()
               )

      assert revoke.decision == "revoke"
      assert [] = Plugins.list_runtime_descriptors(workspace.id, user.id, device.id)
      assert [] = Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)
    end

    test "requires new consent when a deny tombstone no longer matches the current bundle" do
      %{user: user, workspace: workspace, device: device} = account_context()
      approval_device = insert_signing_device!(user, "Changed Approval Device")

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.denied-consent-change",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      %{bundle: bundle} = pin_bundle!(application, user, device)

      assert {:ok, _deny} =
               Plugins.append_consent_event(
                 consent_attrs(%{
                   application_id: application.id,
                   workspace_id: workspace.id,
                   plugin_id: application.plugin_id,
                   version: bundle.version,
                   bundle_hash: bundle.bundle_hash,
                   manifest_hash: bundle.manifest_hash,
                   permissions_hash: bundle.permissions_hash,
                   endpoint_hash: bundle.endpoint_hash,
                   document_scope_hash: bundle.document_scope_hash,
                   user_id: user.id,
                   device_id: device.id,
                   signer_user_id: user.id,
                   signer_device_id: device.id,
                   decision: "deny"
                 })
               )

      assert [] = Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)

      {1, nil} =
        Repo.update_all(
          from(b in PluginBundle, where: b.id == ^bundle.id),
          set: [approved_by_device_id: approval_device.id]
        )

      assert [
               %{
                 signer_device_id: signer_device_id
               }
             ] = Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)

      assert signer_device_id == approval_device.id
    end

    test "stores approval signer in consent subject and verifies signature by consenting device" do
      %{user: user, workspace: workspace, device: device} = account_context()
      approval_device = insert_signing_device!(user, "Approval Device")

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.approval-signer-consent",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      %{bundle: bundle} = pin_bundle!(application, user, device)

      {1, nil} =
        Repo.update_all(
          from(b in PluginBundle, where: b.id == ^bundle.id),
          set: [approved_by_device_id: approval_device.id]
        )

      attrs =
        consent_attrs(%{
          application_id: application.id,
          workspace_id: workspace.id,
          plugin_id: application.plugin_id,
          version: bundle.version,
          bundle_hash: bundle.bundle_hash,
          manifest_hash: bundle.manifest_hash,
          permissions_hash: bundle.permissions_hash,
          endpoint_hash: bundle.endpoint_hash,
          document_scope_hash: bundle.document_scope_hash,
          user_id: user.id,
          device_id: device.id,
          signer_user_id: user.id,
          signer_device_id: approval_device.id
        })

      assert {:ok, consent} = Plugins.append_consent_event(attrs)
      assert consent.device_id == device.id
      assert consent.signer_device_id == approval_device.id

      audit = Repo.get_by!(AuditEvent, type: "plugin.consent.allowed")
      assert audit.actor["user_id"] == user.id
      assert audit.actor["device_id"] == device.id
      refute audit.actor["device_id"] == approval_device.id
    end

    test "requires new consent when the bundle approval signer changes" do
      %{user: user, workspace: workspace, device: device} = account_context()
      approval_device = insert_signing_device!(user, "Replacement Approval Device")

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.approval-signer-change",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      %{bundle: bundle} = pin_bundle!(application, user, device)

      assert {:ok, _consent} =
               Plugins.append_consent_event(
                 consent_attrs(%{
                   application_id: application.id,
                   workspace_id: workspace.id,
                   plugin_id: application.plugin_id,
                   version: bundle.version,
                   bundle_hash: bundle.bundle_hash,
                   manifest_hash: bundle.manifest_hash,
                   permissions_hash: bundle.permissions_hash,
                   endpoint_hash: bundle.endpoint_hash,
                   document_scope_hash: bundle.document_scope_hash,
                   user_id: user.id,
                   device_id: device.id,
                   signer_user_id: user.id,
                   signer_device_id: device.id
                 })
               )

      assert [_descriptor] =
               Plugins.list_runtime_descriptors(workspace.id, user.id, device.id)

      {1, nil} =
        Repo.update_all(
          from(b in PluginBundle, where: b.id == ^bundle.id),
          set: [approved_by_device_id: approval_device.id]
        )

      assert [] = Plugins.list_runtime_descriptors(workspace.id, user.id, device.id)

      assert [
               %{
                 signer_user_id: signer_user_id,
                 signer_device_id: signer_device_id
               }
             ] = Plugins.list_consent_required_descriptors(workspace.id, user.id, device.id)

      assert signer_user_id == user.id
      assert signer_device_id == approval_device.id
    end

    test "rejects consent events for a different application owner" do
      %{user: user, workspace: workspace, device: device} = account_context()
      other_workspace = create_workspace(user)

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.consent",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      %{updated: application, bundle: bundle} = pin_bundle!(application, user, device)

      attrs =
        consent_attrs(%{
          application_id: application.id,
          workspace_id: workspace.id,
          plugin_id: "com.example.consent",
          version: bundle.version,
          bundle_hash: bundle.bundle_hash,
          manifest_hash: bundle.manifest_hash,
          permissions_hash: bundle.permissions_hash,
          endpoint_hash: bundle.endpoint_hash,
          document_scope_hash: bundle.document_scope_hash,
          user_id: user.id,
          device_id: device.id,
          signer_user_id: user.id,
          signer_device_id: device.id
        })

      wrong_workspace_subject =
        attrs
        |> Plugins.consent_subject()
        |> Map.put("workspace_id", other_workspace.id)

      assert {:error, :plugin_consent_event_hash_mismatch} =
               Plugins.append_consent_event(
                 attrs
                 |> Map.put(:workspace_id, other_workspace.id)
                 |> Map.put(
                   :event_hash,
                   Hash.blake3_base64url(JCS.canonical_bytes!(wrong_workspace_subject))
                 )
               )
    end

    test "rejects consent events whose event hash does not match the signed subject" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.consent",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      %{bundle: bundle} = pin_bundle!(application, user, device)

      attrs =
        consent_attrs(%{
          application_id: application.id,
          workspace_id: workspace.id,
          plugin_id: "com.example.consent",
          version: bundle.version,
          bundle_hash: bundle.bundle_hash,
          manifest_hash: bundle.manifest_hash,
          permissions_hash: bundle.permissions_hash,
          endpoint_hash: bundle.endpoint_hash,
          document_scope_hash: bundle.document_scope_hash,
          user_id: user.id,
          device_id: device.id,
          signer_user_id: user.id,
          signer_device_id: device.id
        })

      assert {:error, :plugin_consent_event_hash_mismatch} =
               Plugins.append_consent_event(%{attrs | event_hash: hash("wrong-consent")})

      assert {:error, :plugin_consent_event_signature_invalid} =
               Plugins.append_consent_event(%{attrs | hybrid_signature: %{"sig" => "ok"}})
    end

    test "rejects consent when the current bundle manifest has a dangerous permission grant" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.consent",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      candidate =
        insert_candidate_record!(
          application,
          user,
          device,
          %{
            "id" => application.plugin_id,
            "version" => "1.0.0",
            "permissions" => ["document:read:active", "storage:write:workspace"],
            "network" => %{"endpoints" => []},
            "rendererSlots" => [],
            "documentScopes" => []
          }
        )

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

      assert {:ok, %{application: updated}} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      assert {:ok, bundle} = Plugins.current_bundle_with_pin(updated.id, updated.state_head_hash)

      assert {:error, :plugin_manifest_dangerous_permission_combination} =
               Plugins.append_consent_event(
                 consent_attrs(%{
                   application_id: application.id,
                   workspace_id: workspace.id,
                   plugin_id: application.plugin_id,
                   version: bundle.version,
                   bundle_hash: bundle.bundle_hash,
                   manifest_hash: bundle.manifest_hash,
                   permissions_hash: bundle.permissions_hash,
                   endpoint_hash: bundle.endpoint_hash,
                   document_scope_hash: bundle.document_scope_hash,
                   user_id: user.id,
                   device_id: device.id,
                   signer_user_id: user.id,
                   signer_device_id: device.id
                 })
               )
    end

    test "requires all consent signature subject fields" do
      required_subject_fields = [
        :package_id,
        :application_id,
        :activation_id,
        :owner_scope_kind,
        :application_scope_kind,
        :bundle_hash,
        :manifest_hash,
        :resource_manifest_hash,
        :permissions_hash,
        :endpoint_hash,
        :document_scope_hash,
        :signer_user_id,
        :signer_device_id,
        :workspace_id
      ]

      attrs =
        consent_attrs(%{
          application_id: Ecto.UUID.generate(),
          package_id: Ecto.UUID.generate(),
          activation_id: Ecto.UUID.generate(),
          owner_scope_kind: "workspace",
          application_scope_kind: "workspace",
          workspace_id: Ecto.UUID.generate(),
          plugin_id: "com.example.consent",
          resource_manifest_hash: semantic_hash([]),
          user_id: Ecto.UUID.generate(),
          device_id: Ecto.UUID.generate(),
          signer_user_id: Ecto.UUID.generate(),
          signer_device_id: Ecto.UUID.generate(),
          hybrid_signature: %{"sig" => "ok"}
        })

      for field <- required_subject_fields do
        assert %{^field => ["can't be blank"]} =
                 %PluginConsentEvent{}
                 |> PluginConsentEvent.changeset(Map.delete(attrs, field))
                 |> errors_on()
      end
    end
  end

  describe "plugin runtime bundle loading" do
    test "returns only the current approved bundle for a matching consent head" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.runtime",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.runtime","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"resources":[{"path":"resources/data/index.json","kind":"json","media_type":"application/json"}]}),
          "main.js" => "export default {};",
          "styles.css" => ".runtime { color: red; }",
          "resources/data/index.json" => ~s({"items":[1,2,3]})
        })

      assert {:ok, candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 package_id: application.package_id,
                 workspace_id: workspace.id,
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

      assert {:ok, %{application: updated}} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      assert {:ok, bundle} = Plugins.current_bundle_with_pin(updated.id, updated.state_head_hash)

      assert {:ok, consent} =
               Plugins.append_consent_event(
                 consent_attrs(%{
                   application_id: application.id,
                   workspace_id: workspace.id,
                   plugin_id: application.plugin_id,
                   version: bundle.version,
                   bundle_hash: bundle.bundle_hash,
                   manifest_hash: bundle.manifest_hash,
                   permissions_hash: bundle.permissions_hash,
                   endpoint_hash: bundle.endpoint_hash,
                   document_scope_hash: bundle.document_scope_hash,
                   user_id: user.id,
                   device_id: device.id,
                   signer_user_id: user.id,
                   signer_device_id: device.id
                 })
               )

      assert {:ok, payload} =
               Plugins.runtime_bundle_with_pins(
                 application.id,
                 workspace.id,
                 user.id,
                 device.id,
                 updated.state_head_hash,
                 consent.event_hash
               )

      assert payload.bundle_hash == candidate.bundle_hash
      assert payload.main_js == "export default {};"
      assert payload.styles_css == ".runtime { color: red; }"

      assert [
               %{
                 path: "resources/data/index.json",
                 kind: "json",
                 media_type: "application/json",
                 bytes: ~s({"items":[1,2,3]})
               } = resource
             ] = payload.resources

      assert resource.byte_length == byte_size(~s({"items":[1,2,3]}))
      assert resource.hash == hash(~s({"items":[1,2,3]}))

      assert payload.manifest_json_bytes ==
               ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.runtime","version":"1.0.0","permissions":[],"network":{"endpoints":[]},"resources":[{"path":"resources/data/index.json","kind":"json","media_type":"application/json"}]})
    end

    test "loads runtime proof from stored approval authority after workspace checkpoint advances" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.runtime-authority",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.runtime-authority","version":"1.0.0","permissions":[],"network":{"endpoints":[]}}),
          "main.js" => "export default {};"
        })

      assert {:ok, candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 package_id: application.package_id,
                 workspace_id: workspace.id,
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

      assert {:ok, %{application: updated}} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      assert {:ok, bundle} = Plugins.current_bundle_with_pin(updated.id, updated.state_head_hash)

      advanced_checkpoint = advance_workspace_key_directory_checkpoint!(workspace.id)
      assert advanced_checkpoint.sequence > bundle.approval_authority_checkpoint_sequence

      assert {:ok, consent} =
               Plugins.append_consent_event(
                 consent_attrs(%{
                   application_id: application.id,
                   workspace_id: workspace.id,
                   plugin_id: application.plugin_id,
                   version: bundle.version,
                   bundle_hash: bundle.bundle_hash,
                   manifest_hash: bundle.manifest_hash,
                   permissions_hash: bundle.permissions_hash,
                   endpoint_hash: bundle.endpoint_hash,
                   document_scope_hash: bundle.document_scope_hash,
                   user_id: user.id,
                   device_id: device.id,
                   signer_user_id: user.id,
                   signer_device_id: device.id
                 })
               )

      assert {:ok, payload} =
               Plugins.runtime_bundle_with_pins(
                 application.id,
                 workspace.id,
                 user.id,
                 device.id,
                 updated.state_head_hash,
                 consent.event_hash
               )

      assert payload.approval_proof.approval_authority["event_head_sequence"] ==
               bundle.approval_authority_event_head_sequence

      assert payload.approval_proof.approval_authority["checkpoint_sequence"] ==
               bundle.approval_authority_checkpoint_sequence

      assert get_in(payload.approval_proof, [
               :approval_authority_checkpoint,
               :payload,
               "sequence"
             ]) == bundle.approval_authority_checkpoint_sequence

      assert Enum.any?(
               payload.approval_proof.approval_authority_event_ancestry,
               &(get_in(&1, [:payload, "sequence"]) ==
                   bundle.approval_authority_event_head_sequence and
                   KeyDirectory.event_hash(&1.payload) ==
                     bundle.approval_authority_event_head_hash)
             )
    end

    test "rejects runtime loading when stored candidate bytes no longer match approved hashes" do
      %{user: user, workspace: workspace, device: device} = account_context()

      {:ok, application} =
        create_plugin_application(%{
          workspace_id: workspace.id,
          plugin_id: "com.example.runtime",
          created_by_user_id: user.id,
          state_head_hash: "state-head"
        })

      archive_path =
        plugin_archive_path(%{
          "manifest.json" =>
            ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.runtime","version":"1.0.0"}),
          "main.js" => "export default {}"
        })

      assert {:ok, candidate} =
               Plugins.create_local_bundle_candidate(archive_path, %{
                 package_id: application.package_id,
                 workspace_id: workspace.id,
                 created_by_user_id: user.id,
                 created_by_device_id: device.id
               })

      approval =
        approval_attrs(candidate, %{
          approver_user_id: user.id,
          approver_device_id: device.id,
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS"
        })

      assert {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

      assert {:ok, %{application: updated}} =
               Plugins.apply_package_to_workspace(workspace.id, package.id, user.id, device.id)

      assert {:ok, bundle} = Plugins.current_bundle_with_pin(updated.id, updated.state_head_hash)

      assert {:ok, consent} =
               Plugins.append_consent_event(
                 consent_attrs(%{
                   application_id: application.id,
                   workspace_id: workspace.id,
                   plugin_id: application.plugin_id,
                   version: bundle.version,
                   bundle_hash: bundle.bundle_hash,
                   manifest_hash: bundle.manifest_hash,
                   permissions_hash: bundle.permissions_hash,
                   endpoint_hash: bundle.endpoint_hash,
                   document_scope_hash: bundle.document_scope_hash,
                   user_id: user.id,
                   device_id: device.id,
                   signer_user_id: user.id,
                   signer_device_id: device.id
                 })
               )

      assert {:ok, payload} =
               Plugins.runtime_bundle_with_pins(
                 application.id,
                 workspace.id,
                 user.id,
                 device.id,
                 updated.state_head_hash,
                 consent.event_hash
               )

      assert payload.main_js == "export default {}"

      from(e in PluginPackageEntry,
        where: e.bundle_id == ^bundle.id and e.logical_path == "main.js"
      )
      |> Repo.update_all(set: [hash: hash("tampered-main-js")])

      assert {:error, :plugin_bundle_runtime_hash_mismatch} =
               Plugins.runtime_bundle_with_pins(
                 application.id,
                 workspace.id,
                 user.id,
                 device.id,
                 updated.state_head_hash,
                 consent.event_hash
               )

      from(e in PluginPackageEntry,
        where: e.bundle_id == ^bundle.id and e.logical_path == "main.js"
      )
      |> Repo.update_all(set: [hash: bundle.main_js_hash])

      from(b in PluginBundle, where: b.id == ^bundle.id)
      |> Repo.update_all(set: [main_js_hash: hash("tampered-main-js")])

      assert {:error, :plugin_bundle_runtime_hash_mismatch} =
               Plugins.runtime_bundle_with_pins(
                 application.id,
                 workspace.id,
                 user.id,
                 device.id,
                 updated.state_head_hash,
                 consent.event_hash
               )
    end
  end

  test "sandbox document frames become current only after served frame activation" do
    session =
      Plugins.create_sandbox_document_session(%{
        workspace_id: Ecto.UUID.generate(),
        package_id: Ecto.UUID.generate(),
        application_id: Ecto.UUID.generate(),
        activation_id: Ecto.UUID.generate(),
        owner_scope_kind: "workspace",
        user_id: Ecto.UUID.generate(),
        device_id: Ecto.UUID.generate(),
        auth_session_id: "test-auth-session",
        bundle_id: Ecto.UUID.generate(),
        bundle_hash: hash("bundle"),
        manifest_hash: hash("manifest"),
        resource_manifest_hash: hash("resources"),
        state_head_hash: hash("state"),
        consent_head_hash: hash("consent"),
        consent_epoch: 1,
        capability_grant_id: "capability-grant"
      })

    refute Plugins.current_sandbox_document_frame?(session)
    refute Plugins.activate_sandbox_document_frame?(session)

    :ok = Plugins.mark_sandbox_document_served(session)
    refute Plugins.current_sandbox_document_frame?(session)
    assert Plugins.activate_sandbox_document_frame?(session)
    assert Plugins.current_sandbox_document_frame?(session)
    refute Plugins.current_sandbox_document_frame?(%{session | owner_scope_kind: "user"})
    refute Plugins.current_sandbox_document_frame?(%{session | consent_epoch: 2})

    :ok = Plugins.revoke_sandbox_document_frame(session)
    refute Plugins.current_sandbox_document_frame?(session)
  end

  test "sandbox document frame tracking replaces only the current primary frame" do
    attrs = %{
      workspace_id: Ecto.UUID.generate(),
      package_id: Ecto.UUID.generate(),
      application_id: Ecto.UUID.generate(),
      activation_id: Ecto.UUID.generate(),
      owner_scope_kind: "workspace",
      user_id: Ecto.UUID.generate(),
      device_id: Ecto.UUID.generate(),
      auth_session_id: "test-auth-session",
      bundle_id: Ecto.UUID.generate(),
      bundle_hash: hash("bundle"),
      manifest_hash: hash("manifest"),
      resource_manifest_hash: hash("resources"),
      state_head_hash: hash("state"),
      consent_head_hash: hash("consent"),
      consent_epoch: 1,
      capability_grant_id: "capability-grant"
    }

    primary = Plugins.create_sandbox_document_session(attrs)
    newer_primary = Plugins.create_sandbox_document_session(attrs)

    secondary =
      Plugins.create_sandbox_document_session(
        Map.put(attrs, :sandbox_document_frame_scope, :secondary)
      )

    assert primary.frame_generation != newer_primary.frame_generation
    assert primary.frame_generation != secondary.frame_generation

    :ok = Plugins.mark_sandbox_document_served(primary)
    refute Plugins.activate_sandbox_document_frame?(primary)

    :ok = Plugins.mark_sandbox_document_served(newer_primary)
    assert Plugins.activate_sandbox_document_frame?(newer_primary)
    assert Plugins.current_sandbox_document_frame?(newer_primary)
    refute Plugins.current_sandbox_document_frame?(primary)

    :ok = Plugins.mark_sandbox_document_served(secondary)
    assert Plugins.activate_sandbox_document_frame?(secondary)
    assert Plugins.current_sandbox_document_frame?(secondary)
    assert Plugins.current_sandbox_document_frame?(newer_primary)

    :ok = Plugins.revoke_sandbox_document_frame(secondary)
    refute Plugins.current_sandbox_document_frame?(secondary)
    assert Plugins.current_sandbox_document_frame?(newer_primary)
  end

  defp account_context do
    user = insert_user!()

    workspace = create_workspace(user)

    device_id = Ecto.UUID.generate()
    device_material = TestCrypto.hybrid_device_material(device_id)
    {device_x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)

    device_encryption =
      TestCrypto.hybrid_encryption_public_key_material(
        "device",
        device_id,
        device_x25519_public
      )

    Process.put({:plugin_test_device_material, device_id}, device_material)

    device =
      Repo.insert!(%Device{
        id: device_id,
        user_id: user.id,
        name: "Device",
        device_type: "desktop",
        hybrid_encryption_public_key_material: device_encryption.public,
        encryption_key_id: device_encryption.encryption_key_id,
        hybrid_signing_public_key_material: device_material.public,
        signing_key_id: device_material.signing_key_id,
        approval_signature: %{"sig" => "ok"},
        approval_signature_surface: "device_approval",
        approval_proof: %{"proof" => "ok"},
        key_checkpoint_sequence: 1,
        key_checkpoint_hash: hash("checkpoint:#{device_id}"),
        client_nonce: <<1, 2, 3>>,
        last_seen_at: DateTime.utc_now(),
        created_at: DateTime.utc_now()
      })

    owner_role =
      Repo.get_by!(RefMD.Workspaces.WorkspaceRole,
        workspace_id: workspace.id,
        base_role: "owner"
      )

    identity_material = TestCrypto.hybrid_signing_private_key_material("identity", user.id)
    {identity_x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)

    TestCrypto.insert_test_workspace_key_directory!(
      workspace.id,
      user.id,
      owner_role.id,
      identity_material,
      TestCrypto.hybrid_encryption_public_key_material(
        "identity",
        user.id,
        identity_x25519_public
      ).public,
      device_material.private,
      device_encryption.public
    )

    %{user: user, workspace: workspace, device: device, device_material: device_material}
  end

  defp insert_user! do
    Repo.insert!(%User{
      email: "user-#{System.unique_integer([:positive])}@example.com",
      name: "User",
      account_type: "registered"
    })
  end

  defp insert_signing_device!(user, name) do
    device_id = Ecto.UUID.generate()
    device_material = TestCrypto.hybrid_device_material(device_id)
    {device_x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)

    device_encryption =
      TestCrypto.hybrid_encryption_public_key_material(
        "device",
        device_id,
        device_x25519_public
      )

    Process.put({:plugin_test_device_material, device_id}, device_material)

    Repo.insert!(%Device{
      id: device_id,
      user_id: user.id,
      name: name,
      device_type: "desktop",
      hybrid_encryption_public_key_material: device_encryption.public,
      encryption_key_id: device_encryption.encryption_key_id,
      hybrid_signing_public_key_material: device_material.public,
      signing_key_id: device_material.signing_key_id,
      approval_signature: %{"sig" => "ok"},
      approval_signature_surface: "device_approval",
      approval_proof: %{"proof" => "ok"},
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: hash("checkpoint:#{device_id}"),
      client_nonce: <<1, 2, 3>>,
      last_seen_at: DateTime.utc_now(),
      created_at: DateTime.utc_now()
    })
  end

  defp advance_workspace_key_directory_checkpoint!(workspace_id) do
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    next_event_sequence = checkpoint.covered_event_head_sequence + 1
    policy = Suite.current_suite_policy()

    event_payload =
      KeyDirectory.build_event_payload!(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => next_event_sequence,
        "event_type" => "suite_policy_changed",
        "actor" => %{"signer_kind" => "device"},
        "previous_event_hash" => checkpoint.covered_event_head_hash,
        "body" => %{
          "suite_policy_version" => policy["suite_policy_version"],
          "min_suite_rank" => policy["min_suite_rank"],
          "allowed_suite_ids" => policy["allowed_suite_ids"]
        }
      })

    Repo.insert!(
      Event.changeset(%Event{}, %{
        scope_kind: "workspace",
        scope_id: workspace_id,
        sequence: event_payload["sequence"],
        event_type: event_payload["event_type"],
        event_hash: KeyDirectory.event_hash(event_payload),
        event_body_hash: KeyDirectory.event_body_hash(event_payload["body"]),
        previous_event_hash: event_payload["previous_event_hash"],
        payload: event_payload,
        signatures: [%{"test" => "checkpoint-advanced"}]
      })
    )

    payload =
      checkpoint.payload
      |> Map.put("sequence", checkpoint.sequence + 1)
      |> Map.put(
        "issued_at",
        DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
      )
      |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
      |> Map.put("covered_event_head", %{
        "head_sequence" => event_payload["sequence"],
        "head_hash" => KeyDirectory.event_hash(event_payload)
      })
      |> KeyDirectory.build_checkpoint_payload!()

    %Checkpoint{}
    |> Checkpoint.changeset(%{
      scope_kind: "workspace",
      scope_id: workspace_id,
      sequence: payload["sequence"],
      checkpoint_hash: KeyDirectory.checkpoint_hash(payload),
      previous_checkpoint_hash: Map.get(payload, "previous_checkpoint_hash"),
      covered_event_head_sequence: payload["covered_event_head"]["head_sequence"],
      covered_event_head_hash: payload["covered_event_head"]["head_hash"],
      suite_policy_version: payload["suite_policy_version"],
      min_suite_rank: payload["min_suite_rank"],
      allowed_suite_ids_hash: Suite.canonical_allowed_suite_ids_hash(payload),
      payload: payload,
      signatures: [%{"test" => "checkpoint-advanced"}]
    })
    |> Repo.insert!()
  end

  defp append_workspace_member_authority!(workspace_id, user_id, role) do
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    next_event_sequence = checkpoint.covered_event_head_sequence + 1

    event_payload =
      KeyDirectory.build_event_payload!(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => next_event_sequence,
        "event_type" => "member_added",
        "actor" => %{"signer_kind" => "device"},
        "previous_event_hash" => checkpoint.covered_event_head_hash,
        "body" => %{
          "workspace_id" => workspace_id,
          "user_id" => user_id,
          "role_id" => role.id,
          "base_role" => role.base_role
        }
      })

    Repo.insert!(
      Event.changeset(%Event{}, %{
        scope_kind: "workspace",
        scope_id: workspace_id,
        sequence: event_payload["sequence"],
        event_type: event_payload["event_type"],
        event_hash: KeyDirectory.event_hash(event_payload),
        event_body_hash: KeyDirectory.event_body_hash(event_payload["body"]),
        previous_event_hash: event_payload["previous_event_hash"],
        payload: event_payload,
        signatures: [%{"test" => "member-added"}]
      })
    )

    payload =
      checkpoint.payload
      |> Map.put("sequence", checkpoint.sequence + 1)
      |> Map.put(
        "issued_at",
        DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
      )
      |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
      |> Map.put("covered_event_head", %{
        "head_sequence" => event_payload["sequence"],
        "head_hash" => KeyDirectory.event_hash(event_payload)
      })
      |> KeyDirectory.build_checkpoint_payload!()

    %Checkpoint{}
    |> Checkpoint.changeset(%{
      scope_kind: "workspace",
      scope_id: workspace_id,
      sequence: payload["sequence"],
      checkpoint_hash: KeyDirectory.checkpoint_hash(payload),
      previous_checkpoint_hash: Map.get(payload, "previous_checkpoint_hash"),
      covered_event_head_sequence: payload["covered_event_head"]["head_sequence"],
      covered_event_head_hash: payload["covered_event_head"]["head_hash"],
      suite_policy_version: payload["suite_policy_version"],
      min_suite_rank: payload["min_suite_rank"],
      allowed_suite_ids_hash: Suite.canonical_allowed_suite_ids_hash(payload),
      payload: payload,
      signatures: [%{"test" => "member-added"}]
    })
    |> Repo.insert!()
  end

  defp create_workspace(user) do
    {:ok, workspace} = Workspaces.create_default_workspace(user.id, "Workspace")
    workspace
  end

  defp workspace_role!(workspace_id, base_role) do
    Repo.get_by!(RefMD.Workspaces.WorkspaceRole,
      workspace_id: workspace_id,
      base_role: base_role
    )
  end

  defp pin_bundle!(application, user, device, permissions \\ []) do
    archive_path =
      plugin_archive_path(%{
        "manifest.json" => plugin_manifest_json(application.plugin_id, permissions),
        "main.js" => "export default {}"
      })

    {:ok, candidate} =
      Plugins.create_local_bundle_candidate(archive_path, %{
        package_id: application.package_id,
        workspace_id: application.workspace_id,
        created_by_user_id: user.id,
        created_by_device_id: device.id
      })

    approval =
      approval_attrs(candidate, %{
        approver_user_id: user.id,
        approver_device_id: device.id,
        approval_epoch: 1,
        previous_approval_event_hash: "GENESIS"
      })

    {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

    {:ok, %{application: updated}} =
      Plugins.apply_package_to_workspace(application.workspace_id, package.id, user.id, device.id)

    {:ok, bundle} = Plugins.current_bundle_with_pin(updated.id, updated.state_head_hash)
    %{updated: updated, bundle: bundle, candidate: candidate}
  end

  defp current_frame_generation!(
         application,
         bundle,
         activation,
         consent,
         user_id,
         device_id,
         capability_grant_id
       ) do
    session =
      Plugins.create_sandbox_document_session(%{
        workspace_id: application.workspace_id,
        package_id: application.package_id,
        application_id: application.id,
        activation_id: activation.id,
        owner_scope_kind: "workspace",
        user_id: user_id,
        device_id: device_id,
        auth_session_id: "test-auth-session",
        bundle_id: bundle.id,
        bundle_hash: bundle.bundle_hash,
        manifest_hash: bundle.manifest_hash,
        resource_manifest_hash: bundle.resource_manifest_hash,
        state_head_hash: application.state_head_hash,
        consent_head_hash: consent.event_hash,
        consent_epoch: consent.consent_epoch,
        capability_grant_id: capability_grant_id
      })

    :ok = Plugins.mark_sandbox_document_served(session)
    true = Plugins.activate_sandbox_document_frame?(session)
    session.frame_generation
  end

  defp create_plugin_application(attrs) do
    attrs =
      if Map.get(attrs, :package_id) do
        attrs
      else
        package = create_workspace_package!(attrs)
        Map.put(attrs, :package_id, package.id)
      end

    Plugins.create_application(attrs)
  end

  defp create_workspace_package!(attrs) do
    plugin_id = Map.fetch!(attrs, :plugin_id)
    workspace_id = Map.fetch!(attrs, :workspace_id)

    {:ok, package} =
      Packages.create(%{
        plugin_id: plugin_id,
        version: Map.get(attrs, :version, "1.0.0"),
        owner_scope_kind: "workspace",
        owner_workspace_id: workspace_id,
        created_by_user_id: Map.fetch!(attrs, :created_by_user_id),
        bundle_hash: hash("package-bundle:#{plugin_id}:#{workspace_id}"),
        resource_manifest_hash: hash("package-resources:#{plugin_id}:#{workspace_id}"),
        state_head_hash: "GENESIS"
      })

    package
  end

  defp assert_package_entry_db_rejects(attrs) do
    error =
      assert_raise Ecto.ConstraintError, fn ->
        Repo.transaction(fn ->
          Repo.insert!(struct(PluginPackageEntry, attrs))
        end)
      end

    assert Exception.message(error) =~ "plugin_package_entries_"
  end

  defp package_entry_db_attrs(owner_attrs, overrides) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    id = Map.get(overrides, :id, Ecto.UUID.generate())

    %{
      id: id,
      owner_scope_kind: Map.fetch!(owner_attrs, :owner_scope_kind),
      owner_workspace_id: Map.get(owner_attrs, :owner_workspace_id),
      owner_user_id: Map.get(owner_attrs, :owner_user_id),
      entry_kind: "resource",
      logical_path: "resources/#{Ecto.UUID.generate()}.txt",
      resource_kind: "text",
      media_type: "text/plain",
      byte_length: 2,
      hash: hash("ok"),
      storage_path: "plugin-packages/#{id}",
      status: "candidate",
      created_at: now
    }
    |> Map.merge(overrides)
  end

  defp consent_attrs(overrides) do
    attrs =
      Map.merge(
        %{
          version: "1.0.0",
          bundle_hash: hash("bundle"),
          manifest_hash: hash("manifest"),
          permissions_hash: hash("permissions"),
          endpoint_hash: hash("endpoint"),
          document_scope_hash: hash("document-scope"),
          decision: "allow",
          consent_epoch: 1,
          previous_event_hash: "GENESIS"
        },
        overrides
      )

    attrs = Map.put(attrs, :event_hash, Plugins.consent_subject_hash(attrs))

    if Map.has_key?(attrs, :hybrid_signature) do
      attrs
    else
      Map.put(attrs, :hybrid_signature, consent_signature(attrs))
    end
  end

  defp hash(value), do: Hash.blake3_base64url(value)

  defp plugin_manifest_json(plugin_id, permissions, renderer_slots \\ []) do
    Jason.encode!(%{
      "scope" => %{
        "supportedOwnerScopes" => ["workspace"],
        "defaultOwnerScope" => "workspace",
        "workspaceApplication" => "required"
      },
      "id" => plugin_id,
      "version" => "1.0.0",
      "permissions" => permissions,
      "network" => %{"endpoints" => []},
      "rendererSlots" => renderer_slots,
      "documentScopes" => []
    })
  end

  defp insert_candidate_record!(application, user, device, manifest) do
    manifest_json_bytes = Jason.encode!(manifest)
    main_js = "export default {}"
    styles_css = ""

    %PluginBundleCandidate{}
    |> PluginBundleCandidate.changeset(%{
      package_id: application.package_id,
      workspace_id: application.workspace_id,
      plugin_id: application.plugin_id,
      version: Map.fetch!(manifest, "version"),
      source_kind: "local_upload",
      source_url_hash: "NO_SOURCE_URL",
      archive_hash: hash("archive:#{System.unique_integer([:positive])}"),
      manifest_json: manifest,
      manifest_json_bytes: manifest_json_bytes,
      main_js: main_js,
      styles_css: styles_css,
      manifest_hash: hash(manifest_json_bytes),
      main_js_hash: hash(main_js),
      styles_css_hash: hash(styles_css),
      bundle_hash: Artifact.bundle_hash(main_js, styles_css, manifest_json_bytes),
      permissions_hash: semantic_hash(Map.get(manifest, "permissions", [])),
      endpoint_hash: semantic_hash(get_in(manifest, ["network", "endpoints"]) || []),
      renderer_slots_hash: semantic_hash(Map.get(manifest, "rendererSlots", [])),
      document_scope_hash: semantic_hash(Map.get(manifest, "documentScopes", [])),
      validation_status: "valid",
      validation_errors: [],
      created_by_user_id: user.id,
      created_by_device_id: device.id
    })
    |> Repo.insert!()
  end

  defp semantic_hash(value), do: Hash.blake3_base64url(JCS.canonical_value_bytes!(value))

  defp network_endpoint_manifest(endpoints) do
    %{
      "scope" => %{
        "supportedOwnerScopes" => ["workspace"],
        "defaultOwnerScope" => "workspace",
        "workspaceApplication" => "required"
      },
      "id" => "com.example.network-endpoints",
      "version" => "1.0.0",
      "permissions" => ["network:fetch"],
      "network" => %{"endpoints" => endpoints},
      "rendererSlots" => [],
      "documentScopes" => []
    }
  end

  defp bundle_attrs(application, overrides) do
    attrs =
      Map.merge(
        %{
          application_id: application.id,
          workspace_id: application.workspace_id,
          plugin_id: application.plugin_id,
          version: "1.0.0",
          source_kind: "local_upload",
          source_url_hash: "NO_SOURCE_URL",
          archive_hash: hash("archive"),
          manifest_json: %{"id" => application.plugin_id, "version" => "1.0.0"},
          manifest_json_bytes: "manifest",
          main_js: "main-js",
          styles_css: "styles-css",
          bundle_hash: hash("bundle"),
          manifest_hash: hash("manifest"),
          main_js_hash: hash("main-js"),
          styles_css_hash: hash("styles-css"),
          permissions_hash: hash("permissions"),
          endpoint_hash: hash("endpoint"),
          renderer_slots_hash: hash("renderer-slots"),
          document_scope_hash: hash("document-scope"),
          approval_epoch: 1,
          previous_approval_event_hash: "GENESIS",
          approved_at_ms: 1_775_000_000_000
        },
        overrides
      )

    maybe_signed_bundle_attrs(attrs)
  end

  defp maybe_signed_bundle_attrs(attrs) do
    if Map.get(attrs, :approved_by_user_id) && Map.get(attrs, :approved_by_device_id) do
      approval_attrs =
        attrs
        |> Map.put(:approver_user_id, Map.get(attrs, :approved_by_user_id))
        |> Map.put(:approver_device_id, Map.get(attrs, :approved_by_device_id))
        |> Map.put(:created_at_ms, Map.get(attrs, :approved_at_ms))

      attrs
      |> Map.put(
        :approval_event_hash,
        Plugins.plugin_bundle_approval_subject_hash(attrs, approval_attrs)
      )
      |> Map.put_new(:hybrid_signature, approval_signature(attrs, approval_attrs))
    else
      Map.put(attrs, :approval_event_hash, hash("approval-event"))
    end
  end

  defp approval_attrs(candidate, attrs) do
    attrs =
      attrs
      |> Map.put_new(:workspace_id, candidate.workspace_id)
      |> Map.put_new(:created_at_ms, 1_775_000_000_000)

    approval_event_hash = Plugins.plugin_bundle_approval_subject_hash(candidate, attrs)

    attrs
    |> Map.put(:approval_event_hash, approval_event_hash)
    |> Map.put(:hybrid_signature, approval_signature(candidate, attrs))
  end

  defp approval_signature(candidate, attrs) do
    material = device_material!(Map.fetch!(attrs, :approver_device_id))

    actor = approval_signing_actor(candidate, attrs)

    approval = Plugins.plugin_bundle_approval_subject(candidate, attrs)

    transcript =
      PluginSignature.build_plugin_bundle_approval_transcript!(%{
        actor: actor,
        approval: approval
      })

    Signature.__test_sign_hybrid_signature__(
      "plugin_bundle_approval",
      transcript,
      material.private,
      material.public
    )
  end

  defp invalid_audit_changeset do
    %AuditEvent{}
    |> Ecto.Changeset.change()
    |> Ecto.Changeset.add_error(:type, "forced audit failure")
  end

  defp fetch_audit_hosts(type) do
    AuditEvent
    |> where([e], e.type == ^type)
    |> order_by([e], asc: e.created_at)
    |> Repo.all()
    |> Enum.map(& &1.correlation["canonical_source_host"])
  end

  defp consent_signature(attrs) do
    material = device_material!(Map.fetch!(attrs, :device_id))

    actor =
      signing_actor(
        Map.fetch!(attrs, :user_id),
        Map.fetch!(attrs, :device_id),
        Map.fetch!(attrs, :workspace_id)
      )

    transcript =
      PluginSignature.build_plugin_consent_event_transcript!(%{
        actor: actor,
        consent: Plugins.consent_subject(attrs)
      })

    Signature.__test_sign_hybrid_signature__(
      "plugin_consent_event",
      transcript,
      material.private,
      material.public
    )
  end

  defp approval_signing_actor(
         %PluginBundleCandidate{owner_scope_kind: "user", owner_user_id: owner_user_id},
         attrs
       ) do
    signing_actor(
      Map.fetch!(attrs, :approver_user_id),
      Map.fetch!(attrs, :approver_device_id),
      owner_user_id,
      "user"
    )
  end

  defp approval_signing_actor(_candidate, attrs) do
    signing_actor(
      Map.fetch!(attrs, :approver_user_id),
      Map.fetch!(attrs, :approver_device_id),
      Map.fetch!(attrs, :workspace_id),
      "workspace"
    )
  end

  defp signing_actor(user_id, device_id, scope_id, scope_kind \\ "workspace") do
    device = Repo.get!(Device, device_id)

    %{
      "device_id" => device_id,
      "key_checkpoint_hash" => device.key_checkpoint_hash,
      "key_checkpoint_sequence" => device.key_checkpoint_sequence,
      "key_scope_id" => scope_id,
      "key_scope_kind" => scope_kind,
      "signer_kind" => "device",
      "user_id" => user_id,
      "signing_key_id" => device_material!(device_id).signing_key_id
    }
  end

  defp device_material!(device_id) do
    case Process.get({:plugin_test_device_material, device_id}) do
      nil -> raise "missing plugin test signing material"
      material -> material
    end
  end

  defp uuid_v7?(uuid) when is_binary(uuid) do
    String.length(uuid) == 36 and
      String.at(uuid, 14) == "7" and
      String.at(uuid, 19) in ~w(8 9 a b)
  end

  defp plugin_archive_path(entries) do
    path =
      Path.join(
        System.tmp_dir!(),
        "refmd-plugin-#{System.unique_integer([:positive, :monotonic])}.zip"
      )

    zip_entries =
      Enum.map(entries, fn {name, bytes} ->
        {String.to_charlist(name), bytes}
      end)

    {:ok, _filename} = :zip.create(String.to_charlist(path), zip_entries)
    path
  end
end
