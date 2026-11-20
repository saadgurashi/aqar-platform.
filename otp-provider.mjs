/**
 * OTP Delivery Provider Abstraction — منصة عقار 2.0 (Section 15)
 *
 * Decouples OTP generation/verification from external SMS/WhatsApp/Email providers.
 * Default provider refuses to claim delivery until an approved provider is configured.
 */

export class UnconfiguredOtpProvider {
  async sendOtp() {
    throw new Error(
      'OTP_PROVIDER_NOT_CONFIGURED: مزود إرسال OTP غير معتمد أو غير مُعد بعد (راجع قرارات القسم 15).',
    );
  }
}

/**
 * Strictly for automated tests — captures outbound deliveries in memory without printing secrets.
 */
export class TestOtpProvider {
  constructor(env = process.env.NODE_ENV) {
    if (env === 'production') {
      throw new Error('SECURITY_POLICY_VIOLATION: TestOtpProvider cannot be used in production');
    }
    this.deliveries = [];
  }

  async sendOtp({ destination, code, purpose, expiresInMinutes, requestId }) {
    this.deliveries.push({ destination, code, purpose, expiresInMinutes, requestId });
    return { accepted: true, provider: 'test-memory' };
  }
}
