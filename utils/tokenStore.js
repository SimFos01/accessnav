const revoked = new Set();
module.exports = {
  revoke(token) {
    if (token) revoked.add(token);
  },
  isRevoked(token) {
    return revoked.has(token);
  }
};
