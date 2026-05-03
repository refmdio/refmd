import type { components } from "@/shared/api/schema";

export interface ShareVerificationWorkspaceDevice {
  device_id: string;
  user_id: string;
  signing_public_key: string;
  encryption_public_key: string;
  historical?: boolean;
}

export interface ShareVerificationParticipantDevice {
  share_id: string;
  device_id: string;
  principal_id: string;
  display_name?: string | null;
  signing_public_key: string;
  encryption_public_key: string;
  historical?: boolean;
}

export interface ShareVerificationDirectory {
  workspace_devices: ShareVerificationWorkspaceDevice[];
  share_participant_devices: ShareVerificationParticipantDevice[];
}

type ApiShareVerificationDirectory = components["schemas"]["ShareVerificationDirectory"];

export function normalizeShareVerificationDirectory(
  directory: ApiShareVerificationDirectory,
): ShareVerificationDirectory {
  return {
    workspace_devices: directory.workspace_devices.map(
      (device) => device as unknown as ShareVerificationWorkspaceDevice,
    ),
    share_participant_devices: directory.share_participant_devices.map(
      (device) => device as unknown as ShareVerificationParticipantDevice,
    ),
  };
}
