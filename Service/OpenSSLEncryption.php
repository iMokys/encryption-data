<?php

namespace Drupal\Service;

use Drupal\Core\Site\Settings;
use Drupal\Core\StringTranslation\StringTranslationTrait;

/**
 * OpenSSLEncryption service.
 */
class OpenSSLEncryption {

  use StringTranslationTrait;

  /**
   * Date format which was used for the encryption.
   */
  public const DATE_FORMAT = 'Y-m-d\TH:i:s';

  /**
   * The number of length.
   */
  protected const NUM_LENGTH = 44;

  /**
   * The cipher algorithm.
   */
  private const CIPHER_ALGORITHM = 'aes-256-cbc';

  /**
   * Encrypt text.
   *
   * @param mixed $data
   *   The text to be encrypted.
   * @param string $key
   *   The key to encrypt the text with.
   *
   * @return string
   *   The encrypted text
   *
   * @throws \Exception
   */
  public function encrypt($data, $key = NULL): string {
    if (!$key) {
      $key = $this->getEncryptionKey();
    }
    $this->checkDependencies($key);
    // Remove the base64 encoding from our key.
    $encryption_key = base64_decode($key);
    // Generate an initialization vector.
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(self::CIPHER_ALGORITHM));
    // Encrypt the data using AES 256 encryption in CBC mode using our
    // encryption key and initialization vector.
    $encrypted = openssl_encrypt($data, self::CIPHER_ALGORITHM, $encryption_key, 0, $iv);
    // The $iv is just as important as the key for decrypting,
    // so save it with our encrypted data using a unique separator (|)
    return $this->base64UrlEncode($encrypted . '|' . $iv);
  }

  /**
   * Decrypt text.
   *
   * @param mixed $data
   *   The text to be decrypted.
   * @param string $key
   *   The key to decrypt the text with.
   *
   * @return string
   *   The decrypted text
   *
   * @throws \Exception
   */
  public function decrypt($data, $key = NULL): string {
    if (!$key) {
      $key = $this->getEncryptionKey();
    }
    $this->checkDependencies($key);
    // Remove the base64 encoding from our key.
    $encryption_key = base64_decode($key);
    // To decrypt, split the encrypted data from our IV - our unique
    // separator used was "|".
    list($encrypted_data, $iv) = array_pad(explode('|', $this->base64UrlDecode($data), 2), 2, NULL);
    return openssl_decrypt($encrypted_data, self::CIPHER_ALGORITHM, $encryption_key, 0, $iv);
  }

  /**
   * Gets the `$settings['encryption_key']` value from settings.php.
   *
   * @return string|null
   *   The encryption key or null..
   */
  public function getEncryptionKey() {
    return Settings::get('encryption_key');
  }

  /**
   * Check dependencies for the encryption method.
   *
   * @param string $key
   *   The key to be checked.
   *
   * @throws \Exception
   */
  public function checkDependencies($key = NULL) {
    $errors = [];

    // Check OpenSSL extension availability.
    if (!extension_loaded('openssl')) {
      $errors[] = $this->t('OpenSSL library not installed.');
    }

    // Check key length.
    if (strlen($key) !== self::NUM_LENGTH) {
      $errors[] = $this->t(
        'This encryption method requires a @NUM_LENGTH length key.',
        [
          '@NUM_LENGTH' => self::NUM_LENGTH,
        ]
      );
    }

    if (!empty($errors)) {
      throw new \Exception(implode(';', $errors));
    }

  }

  /**
   * Encode data to Base64URL.
   *
   * @param string $data
   *   The data to encode.
   *
   * @return bool|string
   *   The encoded data, as a string.
   */
  private function base64UrlEncode($data) {
    $b64 = base64_encode($data);
    if ($b64 === FALSE) {
      return FALSE;
    }
    $url = strtr($b64, '+/', '-_');

    return rtrim($url, '=');
  }

  /**
   * Decode data from Base64URL.
   *
   * @param string $data
   *   The data to decode.
   *
   * @return bool|string
   *   The decoded data, as a string.
   */
  private function base64UrlDecode($data) {
    $b64 = strtr($data, '-_', '+/');

    return base64_decode($b64);
  }

}
