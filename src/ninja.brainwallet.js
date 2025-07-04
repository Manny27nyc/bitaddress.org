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
ninja.wallets.brainwallet = {
    isOpen: function () {
        return (document.getElementById("brainwallet").className.indexOf("selected") != -1);
    },

	open: function () {
		document.getElementById("brainarea").style.display = "block";
		document.getElementById("brainpassphrase").focus();
		document.getElementById("brainwarning").innerHTML = ninja.translator.get("brainalertpassphrasewarning");
	},

	close: function () {
		document.getElementById("brainarea").style.display = "none";
	},

	minPassphraseLength: 15,

	view: function () {
		var key = document.getElementById("brainpassphrase").value.toString()
		document.getElementById("brainpassphrase").value = key;
		var keyConfirm = document.getElementById("brainpassphraseconfirm").value.toString()
		document.getElementById("brainpassphraseconfirm").value = keyConfirm;

		if (key == keyConfirm || document.getElementById("brainpassphraseshow").checked) {
			// enforce a minimum passphrase length
			if (key.length >= ninja.wallets.brainwallet.minPassphraseLength) {
				var bytes = Crypto.SHA256(key, { asBytes: true });
				var btcKey = new Bitcoin.ECKey(bytes);
				var isCompressed = document.getElementById("braincompressed").checked;
				btcKey.setCompressed(isCompressed);
				var bitcoinAddress = btcKey.getBitcoinAddress();
				var privWif = btcKey.getBitcoinWalletImportFormat();
				document.getElementById("brainbtcaddress").innerHTML = bitcoinAddress;
				document.getElementById("brainbtcprivwif").innerHTML = privWif;
				ninja.qrCode.showQrCode({
					"brainqrcodepublic": bitcoinAddress,
					"brainqrcodeprivate": privWif
				});
				document.getElementById("brainkeyarea").style.visibility = "visible";
			}
			else {
				alert(ninja.translator.get("brainalertpassphrasetooshort") + ninja.translator.get("brainalertpassphrasewarning"));
				ninja.wallets.brainwallet.clear();
			}
		}
		else {
			alert(ninja.translator.get("brainalertpassphrasedoesnotmatch"));
			ninja.wallets.brainwallet.clear();
		}
	},

	clear: function () {
		document.getElementById("brainkeyarea").style.visibility = "hidden";
	},

	showToggle: function (element) {
		if (element.checked) {
			document.getElementById("brainpassphrase").setAttribute("type", "text");
			document.getElementById("brainpassphraseconfirm").style.visibility = "hidden";
			document.getElementById("brainlabelconfirm").style.visibility = "hidden";
		}
		else {
			document.getElementById("brainpassphrase").setAttribute("type", "password");
			document.getElementById("brainpassphraseconfirm").style.visibility = "visible";
			document.getElementById("brainlabelconfirm").style.visibility = "visible";
		}
	}
};