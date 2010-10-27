/*
 * Code to use with xpc-shell to explore Weave/Sync interactively.
 * Ensure you're launching the shell with --interactive in the Makefile.
 * 
 * Then just:
 * 
 *   SOLO_FILE=$SOME_TEST_JS rlwrap make check-one
 *   
 * and paste in the contents of this file.
 */
  
/*
 * Basic setup. Stolen from head_helpers.js.
 */

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");

do_get_profile();

// Make sure to provide the right OS so crypto loads the right binaries
let OS = "XPCShell";
if ("@mozilla.org/windows-registry-key;1" in Cc) {
  OS = "WINNT";
} else {
  if ("nsILocalFileMac" in Components.interfaces) {
    OS = "Darwin";
  } else {
    OS = "Linux";
  }
}

let XULAppInfo = {
  vendor: "Mozilla",
  name: "XPCShell",
  ID: "{3e3ba16c-1675-4e88-b9c8-afef81b3d2ef}",
  version: "1",
  appBuildID: "20100621",
  platformVersion: "",
  platformBuildID: "20100621",
  inSafeMode: false,
  logConsoleErrors: true,
  OS: OS,
  XPCOMABI: "noarch-spidermonkey",
  QueryInterface: XPCOMUtils.generateQI([Components.interfaces.nsIXULAppInfo, Components.interfaces.nsIXULRuntime])
};

let XULAppInfoFactory = {
  createInstance: function (outer, iid) {
    if (outer != null)
      throw Components.results.NS_ERROR_NO_AGGREGATION;
    return XULAppInfo.QueryInterface(iid);
  }
};

let registrar = Components.manager.QueryInterface(Components.interfaces.nsIComponentRegistrar);
registrar.registerFactory(Components.ID("{fbfae60b-64a4-44ef-a911-08ceb70b9f31}"),
                          "XULAppInfo", "@mozilla.org/xre/app-info;1",
                          XULAppInfoFactory);

let _ = function(some, debug, text, to) print(Array.slice(arguments).join(" "));

let weaveService = Components.classes["@mozilla.org/weave/service;1"].getService();
weaveService.wrappedJSObject.addResourceAlias();

// Attempting to get atob, btoa.
// These *should* be available...
/*
let win = Ci.nsIDOMWindow
let win = require("window-utils").windowIterator().next();
let {Cc, Ci} = require("chrome");
let atob = win.QueryInterface(Ci.nsIDOMWindowInternal).atob;
let btoa = win.QueryInterface(Ci.nsIDOMWindowInternal).btoa;
 */

// Ensuring we get the right source version.
// Components.utils.import("resource://services-crypto/WeaveCrypto.js");
load("~/moz/hg/services/fx-sync/services/crypto/modules/WeaveCrypto.js");


/* 
 * Test code begins here.
 * Pure hackery!
 */

let weaveCrypto = new WeaveCrypto();
let w = weaveCrypto
let n = w.nss;

let passphrase = "passphrase";
let salt = w.generateRandomBytes(16);
let passItem = w.makeSECItem(passphrase, false);
let saltItem = w.makeSECItem(salt, true);
        
// Bug 436577 prevents us from just using SEC_OID_PKCS5_PBKDF2 here
let pbeAlg = w.algorithm;
let cipherAlg = w.algorithm; // ignored by callee when pbeAlg != a pkcs5 mech.
let prfAlg = n.SEC_OID_HMAC_SHA1; // callee picks if SEC_OID_UNKNOWN, but only SHA1 is supported

let keyLength  = 0;    // Callee will pick.
let iterations = 4096; // PKCS#5 recommends at least 1000.

let algid, slot, symKey;
try {
  algid = n.PK11_CreatePBEV2AlgorithmID(pbeAlg, cipherAlg, prfAlg, keyLength, iterations, saltItem.address());
  if (algid.isNull()) 
    throw this.makeException("PK11_CreatePBEV2AlgorithmID failed", Cr.NS_ERROR_FAILURE);

  slot = n.PK11_GetInternalSlot();
  if (slot.isNull())
    throw this.makeException("couldn't get internal slot", Cr.NS_ERROR_FAILURE);

  // algid: typein:211: TypeError: expected type pointer, got SECAlgorithmID.ptr(ctypes.UInt64("0x105a54e70"))
  symKey = n.PK11_PBEKeyGen(slot, algid, passItem.address(), false, null);
  if (symKey.isNull())
    throw this.makeException("PK11_PBEKeyGen failed", Cr.NS_ERROR_FAILURE);
} catch (e) {
  print("deriveKeyFromPassphrase: failed: " + e);
  throw e;
} finally {
  if (algid && !algid.isNull())
    n.SECOID_DestroyAlgorithmID(algid, true);
  if (slot && !slot.isNull())
    n.PK11_FreeSlot(slot);
}

print(symKey);
