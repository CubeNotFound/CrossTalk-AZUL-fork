//
//	Copyright by Koen, 2003,2004,2005
//	http://games.mess.be
//
//	Some code added or altered
//

//
// P2PLib consts
//

// CONNECT_TYPE
var CT_DIRECT		= 0;
var CT_INDIRECT		= 1;
var CT_DISCONNECTED	= 2;

// ERROR_TYPE
var ET_NOERROR		= 0;
var ET_UNEXPECTED	= 1;

// FILE_STATUS
var FS_NOTSTARTED	= 0;
var FS_INPROGRESS	= 1;
var FS_CANCELLED	= 2;
var FS_TRANSFERRED	= 3;

//
// IE helper globals
//
var m_isIE55 = (screen.logicalXDPI)?false:true;

//
// Extended JScript functions
//
if(!Array.prototype.push) {
	function array_push() {
		for(i=0;i<arguments.length;i++){
			this[this.length] = arguments[i];
		}
		return this.length;
	}
	Array.prototype.push = array_push;
}

if(!Array.prototype.pop) {
	function array_pop(){
		lastElement = this[this.length-1];
		this.length = Math.max(this.length-1,0);
		return lastElement;
	}

	Array.prototype.pop = array_pop;
}

String.prototype.startsWith = function(s){
	return (this.substr(0, s.length) == s);
}

String.prototype.endsWith = function(s){
	return (this.substr(this.length - s.length) == s);
}

//
// Preloading stuff
//
var m_preloadImages = new Array();
var m_preloadIndex = 0;
var m_preloadTimerId;
var m_preloadProgress;
var m_preloadComplete;

function preloadImages(imageNames, progressHandler, completeHandler){
	m_preloadProgress = progressHandler;
	m_preloadComplete = completeHandler;

	for(var i in imageNames){
		var img = new Image();
		img.src = "./images/" + imageNames[i];
		img.onerror = img_onerror;
		m_preloadImages.push(img);
	}

	m_preloadTimerId = setInterval("preloadProgress()", 10);
}

function preloadProgress(){
	m_preloadProgress(Math.round((m_preloadIndex + 1) / m_preloadImages.length * 100));

	if (m_preloadIndex == m_preloadImages.length - 1){
		clearInterval(m_preloadTimerId);
		
		m_preloadComplete();
	}
	else{
		var img = m_preloadImages[m_preloadIndex];
		if (img.complete || img.error){
			img.onerror = null;
			m_preloadIndex++;
		}
	}
}

function img_onerror(){
	this.error = true;
}

//
// Language stuff
//
function GetLanguageName() {
	// JavaScript replacement for original VBScript locale detection function
	switch (navigator.browserLanguage.toLowerCase()) {
		case 'nl-nl', 'nl-be':
			// dutch
			return 'nl';
		case 'fr-fr', 'fr-be', 'fr-ca', 'fr-lu', 'fr-ch':
			// french
			return 'fr';
		case 'de-de', 'de-at', 'de-li', 'de-lu', 'de-ch':
			// german
			return 'de';
		case 'hu-hu':
			// hungarian
			return 'hu';
		case 'pt-pt':
			// portuguese (portugal)
			return 'pt';
		case 'sl-sl':
			// slovenian
			return 'sl';
		case 'es-es', 'es-ar', 'es-bo', 'es-cl', 'es-co', 'es-cr', 'es-do', 'es-ec', 'es-gt', 'es-hn', 'es-mx', 'es-ni', 'es-pa', 'es-pe', 'es-pr', 'es-py', 'es-sv', 'es-uy', 'es-ve':
			// spanish
			return 'es';
		case 'sv-se', 'sv-fl':
			// swedish
			return 'sv';
		default:
			// english/unsupported languages
			return 'en';
	}
}

function loadLanguage(name, lang){
	if (!lang){
		if (window.location.search)
			lang = window.location.search.substr(1).toLowerCase();
		else
			lang = GetLanguageName();
	}

	words.XMLDocument.async = false;

	var url = name + "-" + lang + ".xml";
	if (!words.load(url)){
		url = name + "-en.xml";
		if (!words.load(url))
			alert("Failed to locate language file '" + url + "'")
	}
}

function getWord(id){
	var word = id;
	var wordNode = words.selectSingleNode("/words/" + id);
	if (wordNode)
		word = wordNode.text;

	for(var i = 1; i < arguments.length; i++)
		word = word.replace("{" + (i - 1) + "}", arguments[i]);

	return word;
}

//
// P2P helpers
//
function getRemoteUserName(){
	var users = window.external.Users;
	
	for(var i = 0; i < users.Count; i++){
		var user = users.Item(i);
		if (user != users.Me)
			return user.Name;
	}
	return "RemoteUser";
}

function getDisplayName(userName){
	if (userName.length > 20)
		return userName.substr(0, 20) + "..";
	return userName;
}

function iAmInviter(){
	var users = window.external.Users;

	return users.Inviter == users.Me;
}

//
// Other helpers
//
function getRandomInt(min, max){
	return Math.floor((Math.random() * (max - min + 1)) + min);
}

function showHelpFile(helpUrl){
	open(helpUrl, "help", "width=400,location=no,resizable=yes,scrollbars=yes,status=yes,menubar=no,titlebar=no,toolbar=no");
}

function getBuddyScoreUrl(appID){
	return "http://appdirectory.brinkster.net/score/ListBuddyScores.aspx?appid=" + appID + "&uid=" + encodeURI(window.external.Users.Me.Email)
}
