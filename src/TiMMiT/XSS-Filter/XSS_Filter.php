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
    /** @var \voku\helper\AntiXSS interne class */
    private static \voku\helper\AntiXSS $vokuAntiXSS;

    /** @var string[] alle bekende html tags blokkeren */
    private static array $allHtmlTags = array("a", "abbr", "address", "area", "b", "base", "bdi", "bdo", "blockquote", "body", "br", "button", "caption", "cite", "code", "col", "colgroup", "dd", "del", "dfn", "div", "dl", "dt", "em", "fieldset", "font", "form", "head", "hr", "html", "hx", "i", "iframe", "img", "input", "ins", "kbd", "label", "legend", "li", "link", "map", "meta", "noscript", "object", "ol", "optgroup", "option", "p", "param", "pre", "q", "s", "samp", "script", "select", "span", "strong", "style", "sub", "sup", "table", "tbody", "td", "textarea", "tfoot", "th", "thead", "title", "tr", "u", "ul", "var", "article", "aside", "audio", "canvas", "command", "datalist", "details", "dialog", "embed", "figure", "footer", "header", "hgroup", "keygen", "mark", "meter", "nav", "output", "progress", "rp", "rt", "ruby", "section", "source", "time", "video", "acronym", "applet", "basefont", "big", "center", "dir", "frame", "frameset", "menu", "noframes", "small", "strike", "tt");

    /**
     * Check GLOBALS
     *
     * @param bool $overwriteWithCleanedValues true then clean the GLOBAL array's
     * @param bool $blockAllHtmlField true then block all known html fields
     *
     * @return bool true if XSS is detected, false otherwise
     */
    public static function check4XSSInRequestArrays(bool $overwriteWithCleanedValues = false, bool $blockAllHtmlField = false): bool
    {
        if (self::detectXSSInArray($_POST, $overwriteWithCleanedValues, $blockAllHtmlField)) {
            return true;
        }
        if (self::detectXSSInArray($_GET, $overwriteWithCleanedValues, $blockAllHtmlField)) {
            return true;
        }
        if (self::detectXSSInArray($_COOKIE, $overwriteWithCleanedValues, $blockAllHtmlField)) {
            return true;
        }
        return false;
    }


    /**
     * A utility function to manage nested array structures, checking
     * each value for possible XSS. Function returns boolean if XSS is
     * found.
     *
     * @param mixed[] $array An array of data to check, this can be nested arrays.
     * @param bool $overwriteWithCleanedValues true then clean the array.
     * @param bool $blockAllHtmlField true then block all known html fields
     *
     * @return bool True if XSS is detected, false otherwise.
     */
    public static function detectXSSInArray(array &$array, bool $overwriteWithCleanedValues = false, bool $blockAllHtmlField = false): bool
    {
        foreach ($array as $key => $value) {
            if (is_array($value)) {
                return self::detectXSSInArray($array[$key]);
            } else {
                if (!isset(self::$vokuAntiXSS)) {
                    self::$vokuAntiXSS = new AntiXSS();
                    if ($blockAllHtmlField) {
                        self::$vokuAntiXSS->addEvilHtmlTags(self::$allHtmlTags);
                    } else {
                        self::$vokuAntiXSS->addEvilHtmlTags(array('img', 'a', 'b', 'strong', 'i'));
                    }
                    self::$vokuAntiXSS->setStripe4byteChars(true);
                }
                if (is_string($value)) {
                    $cleanItem = self::$vokuAntiXSS->xss_clean($value);
                    if ($overwriteWithCleanedValues) {
                        $array[$key] = $cleanItem;
                    }
                    if (self::$vokuAntiXSS->isXssFound()) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
