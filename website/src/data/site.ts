import release from './release.json';
export { release };
export const releaseURL = `${release.repository}/releases/tag/v${release.version}`;
export const download = (file: string) => `${release.repository}/releases/download/v${release.version}/${file}`;
export const source = (path: string) => `${release.repository}/blob/${release.docsRef}/${path}`;
export const packetExample = `livewire ${release.packetCommand} -in issue.pcap -i eth0`;
export const navigation = [
  { href: '/install/', label: 'Install' },
  { href: '/workflows/', label: 'Workflows' },
  { href: '/secure-replay/', label: 'Secure replay' },
  { href: '/protocols/', label: 'Protocols' },
  { href: '/releases/', label: 'Releases' },
  { href: '/troubleshooting/', label: 'Troubleshooting' },
];
