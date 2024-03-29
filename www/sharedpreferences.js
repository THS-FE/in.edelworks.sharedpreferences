// JavaScript Document
var exec = require('cordova/exec');

var sharedpreferences = {
	getSharedPreferences : function(file, mode,pakage, successCallback, errorCallback){
		cordova.exec(successCallback, errorCallback, 'Sharedpreferences', 'getSharedPreferences', [file, mode,pakage])
	},
	putString: function(key, string, successCallback, errorCallback){
		cordova.exec(successCallback, errorCallback, 'Sharedpreferences', 'putString', [key, string])
	},
	getString: function(key, successCallback, errorCallback){
		cordova.exec(successCallback, errorCallback, 'Sharedpreferences', 'getString', [key])
	},
	putBoolean: function(key, value, successCallback, errorCallback){
		cordova.exec(successCallback, errorCallback, 'Sharedpreferences', 'putBoolean', [key, value])
	},
	getBoolean: function(key, successCallback, errorCallback){
		cordova.exec(successCallback, errorCallback, 'Sharedpreferences', 'getBoolean', [key])
	},
	putInt: function(key, value, successCallback, errorCallback){
		cordova.exec(successCallback, errorCallback, 'Sharedpreferences', 'putInt', [key, value])
	},
	getInt: function(key, successCallback, errorCallback){
		cordova.exec(successCallback, errorCallback, 'Sharedpreferences', 'getInt', [key])
	},
	putLong: function(key, value, successCallback, errorCallback){
		cordova.exec(successCallback, errorCallback, 'Sharedpreferences', 'putLong', [key, value])
	},
	getLong: function(key, successCallback, errorCallback){
		cordova.exec(successCallback, errorCallback, 'Sharedpreferences', 'getLong', [key])
	},
	remove: function(key, successCallback, errorCallback){
		cordova.exec(successCallback, errorCallback, 'Sharedpreferences', 'remove', [key])
	},
	clear: function(successCallback, errorCallback){
		cordova.exec(successCallback, errorCallback, 'Sharedpreferences', 'clear', ["null"])
	}
}

module.exports =  sharedpreferences;
