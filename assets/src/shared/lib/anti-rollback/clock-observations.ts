interface ClockedUpdateLike {
  publicData: {
    signingKeyId: string;
    authorityContextKey?: string;
    clock: number;
  };
}

export function documentClockKey(publicData: {
  signingKeyId: string;
  authorityContextKey?: string;
}): string {
  return publicData.authorityContextKey
    ? `${publicData.authorityContextKey}:${publicData.signingKeyId}`
    : publicData.signingKeyId;
}

export function collectClockObservations<T extends ClockedUpdateLike>(
  updates: readonly T[],
): Map<string, { max: number; seen: Set<number> }> {
  const observations = new Map<string, { max: number; seen: Set<number> }>();

  for (const update of updates) {
    const deviceKey = documentClockKey(update.publicData);
    const clock = update.publicData.clock;
    const existing = observations.get(deviceKey);
    if (existing) {
      existing.max = Math.max(existing.max, clock);
      existing.seen.add(clock);
      continue;
    }
    observations.set(deviceKey, { max: clock, seen: new Set([clock]) });
  }

  return observations;
}

export function getNextClockForDevice(
  clocks: Record<string, number>,
  deviceSigningKeyId?: string | null,
  authorityContextKey?: string | null,
): number {
  if (!deviceSigningKeyId) {
    return 0;
  }
  const clockKey = authorityContextKey
    ? `${authorityContextKey}:${deviceSigningKeyId}`
    : deviceSigningKeyId;
  return (clocks[clockKey] ?? -1) + 1;
}
