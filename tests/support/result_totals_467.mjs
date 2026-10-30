// #467: R47 boundaries recorded by #408's injected HTTPWalletJSON transport.
export function resultTotals467(seeds) {
  const cases = []
  for (const [call, field, entries] of [
    ['listActions', 'totalActions', 'actions'],
    ['listOutputs', 'totalOutputs', 'outputs'],
    ['listCertificates', 'totalCertificates', 'certificates'],
    ['discoverByIdentityKey', 'totalCertificates', 'certificates'],
    ['discoverByAttributes', 'totalCertificates', 'certificates']
  ]) {
    for (const total of [0, 0xffffffff, 2 ** 32, Number.MAX_SAFE_INTEGER, 2 ** 53]) {
      cases.push({ name: `${call}_total_${total}_467`, group: 'row_47', call,
        args: structuredClone(seeds.get(call).args),
        bodyText: JSON.stringify({ [field]: total, [entries]: [] }) })
    }
  }
  return cases
}
