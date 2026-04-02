interface ClockedUpdateLike {
  publicData: {
    signingPubKey: string;
    clock: number;
  };
}

export function collectClockObservations<T extends ClockedUpdateLike>(
  updates: readonly T[],
): Map<string, { max: number; seen: Set<number> }> {
  const observations = new Map<string, { max: number; seen: Set<number> }>();

  for (const update of updates) {
    const deviceKey = update.publicData.signingPubKey;
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
  deviceSigningPubKey?: string | null,
): number {
  if (!deviceSigningPubKey) {
    return 0;
  }
  return (clocks[deviceSigningPubKey] ?? -1) + 1;
}
