// © Licensed Authorship: Manuel J. Nieves (See LICENSE for terms)
/*
 * Copyright (c) 2008–2025 Manuel J. Nieves (a.k.a. Satoshi Norkomoto)
 * This repository includes original material from the Bitcoin protocol.
 *
 * Redistribution requires this notice remain intact.
 * Derivative works must state derivative status.
 * Commercial use requires licensing.
 *
 * GPG Signed: B4EC 7343 AB0D BF24
 * Contact: Fordamboy1@gmail.com
 */
/*
 * Copyright (c) 2008–2025 Manuel J. Nieves (a.k.a. Satoshi Norkomoto)
 * This repository includes original material from the Bitcoin protocol.
 *
 * Redistribution requires this notice remain intact.
 * Derivative works must state derivative status.
 * Commercial use requires licensing.
 *
 * GPG Signed: B4EC 7343 AB0D BF24
 * Contact: Fordamboy1@gmail.com
 */
//https://raw.github.com/bitcoinjs/bitcoinjs-lib/09e8c6e184d6501a0c2c59d73ca64db5c0d3eb95/src/util.js
// Bitcoin utility functions
Bitcoin.Util = {
	/**
	* Cross-browser compatibility version of Array.isArray.
	*/
	isArray: Array.isArray || function (o) {
		return Object.prototype.toString.call(o) === '[object Array]';
	},
	/**
	* Create an array of a certain length filled with a specific value.
	*/
	makeFilledArray: function (len, val) {
		var array = [];
		var i = 0;
		while (i < len) {
			array[i++] = val;
		}
		return array;
	},
	/**
	* Turn an integer into a "var_int".
	*
	* "var_int" is a variable length integer used by Bitcoin's binary format.
	*
	* Returns a byte array.
	*/
	numToVarInt: function (i) {
		if (i < 0xfd) {
			// unsigned char
			return [i];
		} else if (i <= 1 << 16) {
			// unsigned short (LE)
			return [0xfd, i >>> 8, i & 255];
		} else if (i <= 1 << 32) {
			// unsigned int (LE)
			return [0xfe].concat(Crypto.util.wordsToBytes([i]));
		} else {
			// unsigned long long (LE)
			return [0xff].concat(Crypto.util.wordsToBytes([i >>> 32, i]));
		}
	},
	/**
	* Parse a Bitcoin value byte array, returning a BigInteger.
	*/
	valueToBigInt: function (valueBuffer) {
		if (valueBuffer instanceof BigInteger) return valueBuffer;

		// Prepend zero byte to prevent interpretation as negative integer
		return BigInteger.fromByteArrayUnsigned(valueBuffer);
	},
	/**
	* Format a Bitcoin value as a string.
	*
	* Takes a BigInteger or byte-array and returns that amount of Bitcoins in a
	* nice standard formatting.
	*
	* Examples:
	* 12.3555
	* 0.1234
	* 900.99998888
	* 34.00
	*/
	formatValue: function (valueBuffer) {
		var value = this.valueToBigInt(valueBuffer).toString();
		var integerPart = value.length > 8 ? value.substr(0, value.length - 8) : '0';
		var decimalPart = value.length > 8 ? value.substr(value.length - 8) : value;
		while (decimalPart.length < 8) decimalPart = "0" + decimalPart;
		decimalPart = decimalPart.replace(/0*$/, '');
		while (decimalPart.length < 2) decimalPart += "0";
		return integerPart + "." + decimalPart;
	},
	/**
	* Parse a floating point string as a Bitcoin value.
	*
	* Keep in mind that parsing user input is messy. You should always display
	* the parsed value back to the user to make sure we understood his input
	* correctly.
	*/
	parseValue: function (valueString) {
		// TODO: Detect other number formats (e.g. comma as decimal separator)
		var valueComp = valueString.split('.');
		var integralPart = valueComp[0];
		var fractionalPart = valueComp[1] || "0";
		while (fractionalPart.length < 8) fractionalPart += "0";
		fractionalPart = fractionalPart.replace(/^0+/g, '');
		var value = BigInteger.valueOf(parseInt(integralPart));
		value = value.multiply(BigInteger.valueOf(100000000));
		value = value.add(BigInteger.valueOf(parseInt(fractionalPart)));
		return value;
	},
	/**
	* Calculate RIPEMD160(SHA256(data)).
	*
	* Takes an arbitrary byte array as inputs and returns the hash as a byte
	* array.
	*/
	sha256ripe160: function (data) {
		return Crypto.RIPEMD160(Crypto.SHA256(data, { asBytes: true }), { asBytes: true });
	},
	// double sha256
	dsha256: function (data) {
		return Crypto.SHA256(Crypto.SHA256(data, { asBytes: true }), { asBytes: true });
	},
	// duck typing method
	hasMethods: function(obj /*, method list as strings */){
		var i = 1, methodName;
		while((methodName = arguments[i++])){
			if(typeof obj[methodName] != 'function') {
				return false;
			}
		}
		return true;
	}
};