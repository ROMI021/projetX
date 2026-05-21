import { store, broadcastEvent } from './store.js';

export function generateSpoofedIp() {
  const octet1 = Math.floor(Math.random() * (223 - 11) + 11);
  const octet2 = Math.floor(Math.random() * 255);
  const octet3 = Math.floor(Math.random() * 255);
  const octet4 = Math.floor(Math.random() * 254) + 1;
  return `${octet1}.${octet2}.${octet3}.${octet4}`;
}

export function rotateIp() {
  store.currentSpoofedIp = generateSpoofedIp();
  broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[EVASION] Rotation IP déclenchée. Nouvelle IP: ${store.currentSpoofedIp}` });
}

export function generateFakeEntropy() {
  const steps = Math.floor(Math.random() * 20) + 10;
  let entropy = 'm:';
  let x = Math.floor(Math.random() * 500);
  let y = Math.floor(Math.random() * 500);
  for (let i = 0; i < steps; i++) {
      x += Math.floor(Math.random() * 10) - 5;
      y += Math.floor(Math.random() * 10) - 5;
      entropy += `${x},${y};`;
  }
  return entropy;
}
