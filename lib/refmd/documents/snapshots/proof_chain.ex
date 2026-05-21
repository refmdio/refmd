defmodule RefMD.Documents.Snapshots.ProofChain do
  @moduledoc false

  alias RefMD.Crypto.{Blake3, JCS}
  alias RefMD.Repo

  @spec build_snapshot_proof_chain(Ecto.UUID.t(), Ecto.UUID.t() | nil, Ecto.UUID.t() | nil) ::
          [map()]
  def build_snapshot_proof_chain(_document_id, _pinned, nil), do: []

  def build_snapshot_proof_chain(_document_id, pinned_snapshot_id, active_snapshot_id)
      when pinned_snapshot_id == active_snapshot_id,
      do: []

  @proof_chain_cte_sql """
  WITH RECURSIVE chain AS (
    SELECT
      id,
      document_id,
      parent_snapshot_id,
      ciphertext_hash,
      parent_proof_hash,
      snapshot_signature_hash,
      snapshot_admission_event_hash,
      proof_chain_hash,
      0 AS depth
    FROM document_snapshots
    WHERE id = $1 AND document_id = $3
    UNION ALL
    SELECT
      s.id,
      s.document_id,
      s.parent_snapshot_id,
      s.ciphertext_hash,
      s.parent_proof_hash,
      s.snapshot_signature_hash,
      s.snapshot_admission_event_hash,
      s.proof_chain_hash,
      c.depth + 1
    FROM document_snapshots s
    JOIN chain c ON s.id = c.parent_snapshot_id
    WHERE ($2::uuid IS NULL OR s.id != $2) AND s.document_id = $3
  )
  SELECT
    id,
    document_id,
    parent_snapshot_id,
    ciphertext_hash,
    parent_proof_hash,
    snapshot_signature_hash,
    snapshot_admission_event_hash,
    proof_chain_hash
  FROM chain
  ORDER BY depth DESC
  """

  def build_snapshot_proof_chain(document_id, pinned_snapshot_id, active_snapshot_id) do
    result =
      Repo.query(
        @proof_chain_cte_sql,
        [
          Ecto.UUID.dump!(active_snapshot_id),
          if(pinned_snapshot_id, do: Ecto.UUID.dump!(pinned_snapshot_id)),
          Ecto.UUID.dump!(document_id)
        ]
      )

    format_proof_chain(result, pinned_snapshot_id)
  end

  @spec compute_snapshot_proof_link_hash(map()) :: String.t()
  def compute_snapshot_proof_link_hash(snapshot) do
    snapshot
    |> snapshot_proof_link_payload()
    |> JCS.canonical_bytes!()
    |> Blake3.hash_base64url()
  end

  defp format_proof_chain(
         {:ok, %{rows: [[_id, _document_id, oldest_parent | _] | _] = rows}},
         pinned_id
       ) do
    if proof_chain_starts_at_anchor?(oldest_parent, pinned_id) do
      Enum.map(rows, &format_proof_link_row/1)
    else
      []
    end
  end

  defp format_proof_chain(_, _), do: []

  defp proof_chain_starts_at_anchor?(nil, nil), do: true

  defp proof_chain_starts_at_anchor?(oldest_parent, pinned_id),
    do: oldest_parent == Ecto.UUID.dump!(pinned_id)

  defp format_proof_link_row([
         id,
         document_id,
         parent_snapshot_id,
         ciphertext_hash,
         parent_proof_hash,
         snapshot_signature_hash,
         snapshot_admission_event_hash,
         proof_chain_hash
       ]) do
    %{
      protocol: "refmd.snapshot-proof-link",
      version: 1,
      document_id: Ecto.UUID.load!(document_id),
      snapshot_id: Ecto.UUID.load!(id),
      parent_snapshot_id: format_parent_snapshot_id(parent_snapshot_id),
      parent_proof_hash: parent_proof_hash,
      ciphertext_hash: ciphertext_hash,
      snapshot_signature_hash: snapshot_signature_hash,
      snapshot_admission_event_hash: snapshot_admission_event_hash,
      proof_chain_hash: proof_chain_hash
    }
  end

  defp snapshot_proof_link_payload(snapshot) do
    %{
      "protocol" => "refmd.snapshot-proof-link",
      "version" => 1,
      "document_id" => snapshot.document_id,
      "snapshot_id" => snapshot.id,
      "parent_snapshot_id" => snapshot.parent_snapshot_id || "GENESIS",
      "parent_proof_hash" => snapshot.parent_proof_hash,
      "ciphertext_hash" => snapshot.ciphertext_hash,
      "snapshot_signature_hash" => snapshot.snapshot_signature_hash,
      "snapshot_admission_event_hash" => snapshot.snapshot_admission_event_hash
    }
  end

  defp format_parent_snapshot_id(nil), do: "GENESIS"
  defp format_parent_snapshot_id(parent_snapshot_id), do: Ecto.UUID.load!(parent_snapshot_id)
end
