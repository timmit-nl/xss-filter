<?php

/**
 * File that contains the XSS_Filter class
 */

declare(strict_types=1);

namespace TiMMiT;

use voku\helper\AntiXSS;

/**
 * De XSS_Filter
 */
class XSS_Filter
{
    /** @var \voku\helper\AntiXSS interne class */
    private static \voku\helper\AntiXSS $vokuAntiXSS;

    /** @var string[] alle bekende html tags blokkeren (https://nl.wikibooks.org/wiki/HTML/Appendices/Overzicht_elementen)*/
    private static array $allHtmlTags = array("a", "abbr", "address", "area", "b", "base", "bdi", "bdo", "blockquote", "body", "br", "button", "caption", "cite", "code", "col", "colgroup", "dd", "del", "dfn", "div", "dl", "dt", "em", "fieldset", "font", "form", "head", "hr", "html", "hx", "i", "iframe", "img", "input", "ins", "kbd", "label", "legend", "li", "link", "map", "meta", "noscript", "object", "ol", "optgroup", "option", "p", "param", "pre", "q", "s", "samp", "script", "select", "span", "strong", "style", "sub", "sup", "table", "tbody", "td", "textarea", "tfoot", "th", "thead", "title", "tr", "u", "ul", "var", "article", "aside", "audio", "canvas", "command", "datalist", "details", "dialog", "embed", "figure", "footer", "header", "hgroup", "keygen", "mark", "meter", "nav", "output", "progress", "rp", "rt", "ruby", "section", "source", "time", "video", "acronym", "applet", "basefont", "big", "center", "dir", "frame", "frameset", "menu", "noframes", "small", "strike", "tt");

    /** @var bool default waarde voor blockAllHtmlField */
    private static bool $blockAllHtmlField = false;

    /** @var bool default waarde voor setStripe4byteChars */
    private static bool $setStripe4byteChars = true;

    /** @var bool forceer reset bij volgende call */
    private static bool $reset = false;

    /**
     * Check GLOBALS
     *
     * @param bool $overwriteWithCleanedValues true then clean the GLOBAL array's
     * @param null|bool $blockAllHtmlField          true then block all known html fields
     *
     * @return bool true if XSS is detected, false otherwise
     */
    public static function check4XSSInRequestArrays(bool $overwriteWithCleanedValues = false, ?bool $blockAllHtmlField = null): bool
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
     * @param mixed[] $array                      An array of data to check, this can be nested arrays.
     * @param bool $overwriteWithCleanedValues true then clean the array.
     * @param null|bool $blockAllHtmlField          true then block all known html fields
     *
     * @return bool True if XSS is detected, false otherwise.
     */
    public static function detectXSSInArray(array &$array, bool $overwriteWithCleanedValues = false, ?bool $blockAllHtmlField = null): bool
    {
        foreach ($array as $key => $value) {
            if (is_array($value)) {
                return self::detectXSSInArray($array[$key]);
            } else {
                self::loadVokuAntiXXSIfNeeded($blockAllHtmlField);

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

    /**
     * loadVokuIfNeeded
     *
     * @param null|bool $blockAllHtmlField true then block all known html fields
     *
     * @return bool True if vokuXSS needed to be loaded.
     */
    private static function loadVokuAntiXXSIfNeeded(bool $blockAllHtmlField = null): bool
    {
        if (is_null($blockAllHtmlField)) {
            $blockAllHtmlField = self::$blockAllHtmlField;
        }

        if (
            !isset(self::$vokuAntiXSS) ||
            self::$reset ||
            self::$blockAllHtmlField != $blockAllHtmlField
        ) {
            self::$vokuAntiXSS = new AntiXSS();
            self::$blockAllHtmlField = $blockAllHtmlField;
            if ($blockAllHtmlField) {
                self::$vokuAntiXSS->addEvilHtmlTags(self::$allHtmlTags);
            } else {
                self::$vokuAntiXSS->addEvilHtmlTags(array('img', 'a', 'b', 'strong', 'i'));
            }
            if (self::$setStripe4byteChars) {
                self::$vokuAntiXSS->setStripe4byteChars(true);
            }
            return true;
        }
        return false;
    }

    /**
     * cleanString
     *
     * @param string $value             string that need to be cleaned
     * @param bool $blockAllHtmlField true then block all known html fields
     *
     * @return string
     */
    public static function cleanString(string $value, bool $blockAllHtmlField = false): string
    {
        self::loadVokuAntiXXSIfNeeded($blockAllHtmlField);

        return self::$vokuAntiXSS->xss_clean($value);
    }

    /**
     * reset
     *
     * @return bool TrueXSS if voku is reset.
     */
    public static function reset(): bool
    {
        return self::$reset = true;
    }
}
