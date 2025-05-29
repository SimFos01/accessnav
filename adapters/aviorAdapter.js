// adapters/aviorMobikeyAdapter.js
const axios = require('axios');
const logger = require('../utils/logger');

const mobikeyUrl = (responseType, device, password) =>
  `http://www.mobikey.eu/cmd/${responseType}/${device}/pwd/${password}`;

exports.open = async (adapterData) => {
  const { device, password, out } = adapterData;
  if (!device || !password || !out) throw new Error('adapterData mangler device, password eller out');

  const url = mobikeyUrl('J', device, password);
  const safeUrl = mobikeyUrl('J', device, '***');
  const command = `OUT${out}=1`;
  try {
    const res = await axios.post(url, command, {
      headers: { 'Content-Type': 'text/plain' }
    });
    logger.debug(`[MOBIKEY] OPEN: ${safeUrl} →`, res.data);
    return res.data;
  } catch (err) {
    console.error('[MOBIKEY] Feil ved OPEN:', err.message);
    throw new Error('Kunne ikke åpne via Mobikey');
  }
};

exports.lock = async (adapterData) => {
  const { device, password, out } = adapterData;
  if (!device || !password || !out) throw new Error('adapterData mangler device, password eller out');

  const url = mobikeyUrl('J', device, password);
  const safeUrl = mobikeyUrl('J', device, '***');
  const command = `OUT${out}=0`;
  try {
    const res = await axios.post(url, command, {
      headers: { 'Content-Type': 'text/plain' }
    });
    logger.debug(`[MOBIKEY] LOCK: ${safeUrl} →`, res.data);
    return res.data;
  } catch (err) {
    console.error('[MOBIKEY] Feil ved LOCK:', err.message);
    throw new Error('Kunne ikke låse via Mobikey');
  }
};
