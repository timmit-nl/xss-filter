<?php

/**
 * File that contains the XSS_Filter class
 */

namespace TiMMiT;

use voku\helper\AntiXSS;

/**
 * De XSS_Filter
 */
class XSS_Filter
{
    /**
     * Check GLOBALS
     *
     * @param bool $overwriteWithCleanedValues true then clean the GLOBAL array's
     * @return bool
     *  true if XSS is detected, false otherwise
     */
    public static function check4XSSInRequestArrays(bool $overwriteWithCleanedValues = false): bool
    {
        if (self::detectXSSInArray($_POST, $overwriteWithCleanedValues)) {
            return true;
        }
        if (self::detectXSSInArray($_GET, $overwriteWithCleanedValues)) {
            return true;
        }
        if (self::detectXSSInArray($_COOKIE, $overwriteWithCleanedValues)) {
            return true;
        }
        return false;
    }


    /**
     * A utility function to manage nested array structures, checking
     * each value for possible XSS. Function returns boolean if XSS is
     * found.
     *
     * @param array $array An array of data to check, this can be nested arrays.
     * @param bool $overwriteWithCleanedValues true then clean the array.
     * @return bool True if XSS is detected, false otherwise.
     */
    public static function detectXSSInArray(array &$array, bool $overwriteWithCleanedValues = false): bool
    {
        foreach ($array as $key => $value) {
            if (is_array($value)) {
                return self::detectXSSInArray($array[$key]);
            } else {
                $antiXss = new AntiXSS();
                $cleanItem = $antiXss->xss_clean($value);
                if ($overwriteWithCleanedValues) {
                    $array[$key] = $cleanItem;
                }
                if ($antiXss->isXssFound()) {
                    return true;
                }
            }
        }
        return false;
    }
}
