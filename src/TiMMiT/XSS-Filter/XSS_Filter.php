<?php
/**
 * File that contains the XSS_Filter class
 */
namespace TiMMiT;

/**
 * De XSS_Filter Based on: https://raw.githubusercontent.com/symphonycms/xssfilter/master/extension.driver.php
 */
	class XSS_Filter {
		/**
		 * @var boolean match all known html tags
		 */
		protected static $matchAllTags = true;

		/**
		* Over, legacy
		* @return array
		*/
		public function about() {
			return array(
				'name' => 'Cross-Site Scripting (XSS) Filter',
				'version' => '1.2',
				'release-date' => '2013-07-01',
				'author' => array(
					'name' => 'Symphony Team',
					'website' => 'http://getsymphony.com/',
					'email' => 'team@getsymphony.com'
				),
				'description' => 'Protect yourself against XSS attacks in form submissions.'
			);
		}

		/**
		 * Check GLOBALS
		 *
		 * @return boolean
		 *  true if XSS is detected, false otherwise
		 */
		public static function check4XSSInRequestArrays() {
			if(self::detectXSSInArray($_POST)){
				return TRUE;
			}
			if(self::detectXSSInArray($_GET)){
				return TRUE;
			}
			if(self::detectXSSInArray($_COOKIE)){
				return TRUE;
			}
			return FALSE;
		}


		/**
		 * A utility function to manage nested array structures, checking
		 * each value for possible XSS. Function returns boolean if XSS is
		 * found.
		 *
		 * @param array $array
		 *  An array of data to check, this can be nested arrays.
		 * @return boolean
		 *  True if XSS is detected, false otherwise
		 */
		public static function detectXSSInArray(array $array) {
			foreach($array as $value) {
				if(is_array($value)) {
					return self::detectXSSInArray($value);
				}
				else {
					if(self::detectXSS($value) === TRUE) return TRUE;
				}
			}

			return FALSE;
		}

		/**
		 * Given a string, this function will determine if it potentially an
		 * XSS attack and return boolean.
		 *
		 * @param string $string
		 *  The string to run XSS detection logic on
		 * @return boolean
		 *  True if the given `$string` contains XSS, false otherwise.
		 */
		public static function detectXSS($string) {
			$contains_xss = FALSE;

			// Skip any null or non string values
			if(is_null($string) || !is_string($string)) {
				return $contains_xss;
			}

			// Keep a copy of the original string before cleaning up
			$orig = $string;

			// URL decode
			$string = urldecode($string);

			// Convert Hexadecimals
			//$string = preg_replace('!(&#|\\\)[xX]([0-9a-fA-F]+);?!e','chr(hexdec("$2"))', $string);
			$string = preg_replace_callback('!(&#|\\\)[xX]([0-9a-fA-F]+);?!',
				function($matches) {
					return chr(hexdec($matches[2]));
				},
				$string);

			// Clean up entities
			$string = preg_replace('!(&#0+[0-9]+)!','$1;',$string);
			// $string = preg_replace_callback('!(&#0+[0-9]+)!',
			// 	function($matches) {
			// 		return $matches[1];
			// 	},
			// 	$string);

			// Decode entities
			$string = html_entity_decode($string, ENT_NOQUOTES, 'UTF-8');

			// Strip whitespace characters
			$string = preg_replace('!\s!','',$string);

			// Set the patterns we'll test against
			$patterns = array(
				// Match any attribute starting with "on" or xmlns
				'#(<[^>]+[\x00-\x20\"\'\/])(on|xmlns)[^>]*>?#iUu',

				// Match javascript:, livescript:, vbscript: and mocha: protocols
				'!((java|live|vb)script|mocha|feed|data):(\w)*!iUu',
				'#-moz-binding[\x00-\x20]*:#u',

				// Match style attributes
				'#(<[^>]+[\x00-\x20\"\'\/])style=[^>]*>?#iUu',

				// Match href attributes
				'#(<[^>]+[\x00-\x20\"\'\/])href=[^>]*>?#iUu',
			);

			if(self::$matchAllTags){
				$patterns[] = '#</*(a|abbr|acronym|address|applet|area|article|aside|audio|b|base|basefont|bdi|bdo|big|blockquote|body|br|button|canvas|caption|center|cite|code|col|colgroup|data|datalist|dd|del|details|dfn|dialog|dir|div|dl|dt|em|embed|fieldset|figcaption|figure|font|footer|form|frame|frameset|h1|h2|h3|h4|h5|h6|head|header|hr|html|i|iframe|img|input|ins|kbd|label|legend|li|link|main|map|mark|meta|meter|nav|noframes|noscript|object|ol|optgroup|option|output|p|param|picture|pre|progress|q|rp|rt|ruby|s|samp|script|section|select|small|source|span|strike|strong|style|sub|summary|sup|svg|table|tbody|td|template|textarea|tfoot|th|thead|time|title|tr|track|tt|u|ul|var|video|wbr)[^>]*>?#i';
			} else {
				$patterns[] = '#</*(applet|meta|xml|blink|link|style|script|embed|object|iframe|frame|frameset|ilayer|layer|bgsound|title|base)[^>]*>?#i';
			}

			foreach($patterns as $pattern) {
				// Test both the original string and clean string
				if(preg_match($pattern, $string) || preg_match($pattern, $orig)){
					$contains_xss = TRUE;
				}
				if($contains_xss === TRUE){
					return TRUE;
				}
			}

			return FALSE;
		}

	}