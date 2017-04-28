<?php
/**
 * Magento
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Open Software License (OSL 3.0)
 * that is bundled with this package in the file LICENSE.txt.
 * It is also available through the world-wide-web at this URL:
 * http://opensource.org/licenses/osl-3.0.php
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to license@magentocommerce.com so we can send you a copy immediately.
 *
 * DISCLAIMER
 *
 * Do not edit or add to this file if you wish to upgrade Magento to newer
 * versions in the future. If you wish to customize Magento for your
 * needs please refer to http://www.magentocommerce.com for more information.
 *
 * @category  Nosto
 * @package   Nosto_Tagging
 * @author    Nosto Solutions Ltd <magento@nosto.com>
 * @copyright Copyright (c) 2013-2017 Nosto Solutions Ltd (http://www.nosto.com)
 * @license   http://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

require_once __DIR__ . '/../bootstrap.php'; // @codingStandardsIgnoreLine
require_once Mage::getBaseDir('lib') . '/phpseclib/Crypt/Random.php';
require_once Mage::getBaseDir('lib') . '/phpseclib/Crypt/AES.php';

/**
 * Helper class for managing Nosto accounts.
 * Includes methods for saving, removing and finding accounts for a specific
 * store.
 *
 * @category Nosto
 * @package  Nosto_Tagging
 * @author   Nosto Solutions Ltd <magento@nosto.com>
 */
class Nosto_Tagging_Helper_Export extends Nosto_Helper_AbstractExportHelper
{
    /**
     * @inheritdoc
     */
    public static function encrypt($secret, $data)
    {
        $iv = self::createIv(16);
        $cipher = new Crypt_AES(CRYPT_AES_MODE_CBC);
        $cipher->setKey($secret);
        $cipher->setIV($iv);
        $cipherText = $cipher->encrypt(Nosto_Helper_SerializationHelper::serialize($data));
        // Prepend the IV to the cipher string so that nosto can parse and use it.
        // There is no security concern with sending the IV as plain text.
        $data = $iv . $cipherText;

        return $data;
    }

    /**
     * Generates random bytes
     *
     * @param $length
     * @throws Nosto_NostoException
     * @return string
     */
    public static function createIv($length)
    {
        $iv = null;
        if (extension_loaded('openssl')) {
            $iv = openssl_random_pseudo_bytes($length);
        } elseif (extension_loaded('mcrypt')) {
            $iv = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
        } else {
            throw new Nosto_NostoException(
                'Could not create iv. Missing both, openssl and mcrypt extensions'
            );
        }

        return $iv;
    }
}
