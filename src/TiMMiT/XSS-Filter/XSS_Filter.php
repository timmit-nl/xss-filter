<?php
/**
 * File that contains the XSS_Filter class
 */
namespace TiMMiT;

use voku\helper\AntiXSS;

/**
 * De XSS_Filter
 */
	class XSS_Filter {
		/**
		 * Check GLOBALS
		 *
		 * @return boolean
		 *  true if XSS is detected, false otherwise
		 */
		public static function check4XSSInRequestArrays() {
			if(self::detectXSSInArray($_POST)){
				return true;
			}
			if(self::detectXSSInArray($_GET)){
				return true;
			}
			if(self::detectXSSInArray($_COOKIE)){
				return true;
			}
			return false;
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
		public static function detectXSSInArray(array &$array) {
			foreach($array as $key=>$value) {
				if(is_array($value)) {
					return self::detectXSSInArray($array[$key]);
				} else {
					$antiXss = new AntiXSS();
					$array[$key] = $antiXss->xss_clean($value);
					if($antiXss->isXssFound()){
						return true;
					}
				}
			}
			return false;
		}

	}
