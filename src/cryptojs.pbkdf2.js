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
/*!
* Crypto-JS v2.5.4	PBKDF2.js
* http://code.google.com/p/crypto-js/
* Copyright (c) 2009-2013, Jeff Mott. All rights reserved.
* http://code.google.com/p/crypto-js/wiki/License
*/
(function () {

	// Shortcuts
	var C = Crypto,
		util = C.util,
		charenc = C.charenc,
		UTF8 = charenc.UTF8,
		Binary = charenc.Binary;

	C.PBKDF2 = function (password, salt, keylen, options) {

		// Convert to byte arrays
		if (password.constructor == String) password = UTF8.stringToBytes(password);
		if (salt.constructor == String) salt = UTF8.stringToBytes(salt);
		/* else, assume byte arrays already */

		// Defaults
		var hasher = options && options.hasher || C.SHA1,
			iterations = options && options.iterations || 1;

		// Pseudo-random function
		function PRF(password, salt) {
			return C.HMAC(hasher, salt, password, { asBytes: true });
		}

		// Generate key
		var derivedKeyBytes = [],
			blockindex = 1;
		while (derivedKeyBytes.length < keylen) {
			var block = PRF(password, salt.concat(util.wordsToBytes([blockindex])));
			for (var u = block, i = 1; i < iterations; i++) {
				u = PRF(password, u);
				for (var j = 0; j < block.length; j++) block[j] ^= u[j];
			}
			derivedKeyBytes = derivedKeyBytes.concat(block);
			blockindex++;
		}

		// Truncate excess bytes
		derivedKeyBytes.length = keylen;

		return options && options.asBytes ? derivedKeyBytes :
		options && options.asString ? Binary.bytesToString(derivedKeyBytes) :
		util.bytesToHex(derivedKeyBytes);

	};

})();