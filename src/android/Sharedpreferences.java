package in.edelworks.sharedpreferences;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaWebView;
import org.json.JSONArray;
import org.json.JSONException;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;

public class Sharedpreferences extends CordovaPlugin {
	public static final String GET_SHARED_PREFERENCES = "getSharedPreferences";
	public static final String PUT_STRING = "putString";
	public static final String GET_STRING = "getString";
	public static final String PUT_BOOLEAN = "putBoolean";
	public static final String GET_BOOLEAN = "getBoolean";
	public static final String PUT_INT = "putInt";
	public static final String GET_INT = "getInt";
	public static final String PUT_FLOAT = "putFloat";
	public static final String GET_FLOAT = "getFloat";
	public static final String PUT_LONG = "putLong";
	public static final String GET_LONG = "getLong";
	public static final String REMOVE = "remove";
	public static final String CLEAR = "clear";
	public static final String SHARED_PREFERENCES = "SharedPreferences";
	public static String PREF_FILE = "";
	public static final String[] MODE_ARRAY = { "MODE_APPEND", "MODE_PRIVATE",
			"MODE_WORLD_READABLE", "MODE_MULTI_PROCESS" };// 新增模式
	SharedPreferences SharedPref;
	SharedPreferences.Editor editor;

	@Override
	public boolean execute(String action, JSONArray args,
			CallbackContext callbackContext) throws JSONException {
		// create shared Preferences
		// two param filename and mode
		// returns true if created with success message and false if not with
		// exception message
		if (GET_SHARED_PREFERENCES.equals(action)) {
			PREF_FILE = args.getString(0);
			String modeType = args.getString(1);
			String pakageName = args.getString(2);
			Context context = null;
			if (pakageName != null && !pakageName.equals("")) {
				try {
					context = cordova
							.getActivity()
							.getApplicationContext()
							.createPackageContext(pakageName,
									Context.CONTEXT_IGNORE_SECURITY);
				} catch (PackageManager.NameNotFoundException e) {
					e.printStackTrace();
				}
			} else {
				context = cordova.getActivity();
			}
			if (in_array(MODE_ARRAY, modeType)) {
				if (modeType.equals("MODE_APPEND")) {
					try {
						SharedPref = context.getSharedPreferences(PREF_FILE,
								Context.MODE_APPEND);
					} catch (Exception e) {
						callbackContext
								.error("Error creating Shared Preferences"
										+ e.getMessage());
						return false;
					}
				} else if (modeType.equals("MODE_PRIVATE")) {
					try {
						SharedPref = context.getSharedPreferences(PREF_FILE,
								Context.MODE_APPEND);
					} catch (Exception e) {
						callbackContext
								.error("Error creating Shared Preferences"
										+ e.getMessage());
						return false;
					}
				} else if (modeType.equals("MODE_WORLD_READABLE")) {// 新增模式
					try {
						SharedPref = context.getSharedPreferences(PREF_FILE,
								Context.MODE_WORLD_READABLE);
					} catch (Exception e) {
						callbackContext
								.error("Error creating Shared Preferences"
										+ e.getMessage());
						return false;
					}
				} else if (modeType.equals("MODE_MULTI_PROCESS")) {// 新增模式
																	// 多进程数据检查是否改变
					try {
						SharedPref = context.getSharedPreferences(PREF_FILE,
								Context.MODE_WORLD_READABLE
										| Context.MODE_MULTI_PROCESS);
					} catch (Exception e) {
						callbackContext
								.error("Error creating Shared Preferences"
										+ e.getMessage());
						return false;
					}
				}
				callbackContext.success("Shared Preferences Created");
				return true;
			} else {
				callbackContext.error("Invalid Mode provided");
				return false;
			}
			// Put a Sting into the Shared Preferences File
			// params key and value String type
		} else if (PUT_STRING.equals(action)) {
			editor = SharedPref.edit();
			try {
				String key = encrypt(args.getString(0));
				String value = encrypt(args.getString(1));
				editor.putString(key, value);
				editor.commit();
			} catch (Exception e) {
				callbackContext.error("Error editing Key " + args.getString(0)
						+ " with value " + args.getString(1) + e.getMessage());
				return false;
			}
			callbackContext.success("Added Value " + args.getString(1)
					+ " to Preferences key " + args.getString(0));
			return true;
		} else if (GET_STRING.equals(action)) {
			String KeyVal;
			try {
				String key = encrypt(args.getString(0));
				if (SharedPref.contains(key)) {
					KeyVal = SharedPref.getString(key, "");
					String realVal = decrypt(KeyVal);
					callbackContext.success(realVal);
					return true;
				} else {
					callbackContext.error("No data");
					return false;
				}
			} catch (Exception e) {
				callbackContext.error("Could Not Retreive " + args.getString(0)
						+ e.getMessage());
				return false;
			}
		} else if (PUT_BOOLEAN.equals(action)) {
			editor = SharedPref.edit();
			boolean isCommit = false;
			try {
				editor.putBoolean(args.getString(0), args.getBoolean(1));
				isCommit = editor.commit();
			} catch (Exception e) {
				callbackContext.error("Error editing Key " + args.getString(0)
						+ " with value " + args.getBoolean(1) + e.getMessage());
				return false;
			}
			callbackContext.success("Added Value " + args.getBoolean(1)
					+ " to Preferences key " + args.getString(0) + "isCommit:"
					+ isCommit);
			return true;
		} else if (GET_BOOLEAN.equals(action)) {
			Boolean KeyVal;
			try {
				if (SharedPref.contains(args.getString(0))) {
					KeyVal = SharedPref.getBoolean(args.getString(0), false);
					if (KeyVal.equals(true)) {
						callbackContext.success(1);
					} else {
						callbackContext.success(0);
					}
					return true;
				} else {
					callbackContext.error("No data");
					return false;
				}
			} catch (Exception e) {
				callbackContext.error("Could Not Retreive " + args.getString(0)
						+ e.getMessage());
				return false;
			}
		} else if (PUT_INT.equals(action)) {
			editor = SharedPref.edit();
			try {
				String key = encrypt(args.getString(0));
				editor.putInt(key, args.getInt(1));
				editor.commit();
			} catch (Exception e) {
				callbackContext.error("Error editing Key " + args.getString(0)
						+ " with value " + args.getInt(1) + e.getMessage());
				return false;
			}
			callbackContext.success("Added Value " + args.getInt(1)
					+ " to Preferences key " + args.getString(0));
			return true;
		} else if (GET_INT.equals(action)) {
			Integer KeyVal;
			try {
				String key = encrypt(args.getString(0));
				if (SharedPref.contains(key)) {
					KeyVal = SharedPref.getInt(key, 0);
					callbackContext.success(KeyVal);
					return true;
				} else {
					callbackContext.error("No data");
					return false;
				}
			} catch (Exception e) {
				callbackContext.error("Could Not Retreive " + args.getString(0)
						+ e.getMessage());
				return false;
			}
		} else if (PUT_LONG.equals(action)) {
			editor = SharedPref.edit();
			try {
				editor.putLong(args.getString(0), args.getLong(1));
				editor.commit();
			} catch (Exception e) {
				callbackContext.error("Error editing Key " + args.getString(0)
						+ " with value " + args.getLong(1) + e.getMessage());
				return false;
			}
			callbackContext.success("Added Value " + args.getLong(1)
					+ " to Preferences key " + args.getString(0));
			return true;
		} else if (GET_LONG.equals(action)) {
			Long KeyVal;
			try {
				if (SharedPref.contains(args.getString(0))) {
					KeyVal = SharedPref.getLong(args.getString(0), 0);
					callbackContext.success(KeyVal.toString());
					return true;
				} else {
					callbackContext.error("No data");
					return false;
				}
			} catch (Exception e) {
				callbackContext.error("Could Not Retreive " + args.getString(0)
						+ e.getMessage());
				return false;
			}
		} else if (REMOVE.equals(action)) {
			editor = SharedPref.edit();
			try {
				editor.remove(args.getString(0));
				editor.commit();
			} catch (Exception e) {
				callbackContext.error("Error editing Key " + args.getString(0)
						+ " with value " + args.getLong(1) + e.getMessage());
				return false;
			}
			callbackContext.success("Removed Value from Key "
					+ args.getString(0));
			return true;
		} else if (CLEAR.equals(action)) {
			editor = SharedPref.edit();
			try {
				editor.clear();
				editor.commit();
			} catch (Exception e) {
				callbackContext.error("Could Not Clear Shared preference File "
						+ e.getMessage());
				return false;
			}
			callbackContext.success("Cleared preference File ");

			return true;
		} else {
			callbackContext.error("Invalid Action");
			return false;
		}
	}

	public static boolean in_array(String[] haystack, String needle) {
		for (int i = 0; i < haystack.length; i++) {
			if (haystack[i].equals(needle)) {
				return true;
			}
		}
		return false;
	}

	private SimpleCryptoUtil simpleCryptoUtil;

	@Override
	public void initialize(CordovaInterface cordova, CordovaWebView webView) {
		// TODO Auto-generated method stub
		super.initialize(cordova, webView);
		simpleCryptoUtil = new SimpleCryptoUtil();
	}

	/**
	 * 加密
	 *
	 * @param str
	 */
	private String encrypt(String str) {
		return simpleCryptoUtil.encode(str);
	}

	/**
	 * 解密
	 *
	 * @param str
	 */
	private String decrypt(String str) {
		return simpleCryptoUtil.decode(str);
	}

	/**
	 * 加密解密帮助
	 *
	 * @author Administrator
	 *
	 */
	private class SimpleCryptoUtil {
		public SimpleCryptoUtil() {
		}

		 static final String algorithmStr = "AES/ECB/PKCS5Padding";

		    private byte[] encrypt(String content, String password)
		    {
		        try
		        {
		            byte[] keyStr = getKey(password);
		            SecretKeySpec key = new SecretKeySpec(keyStr, "AES");
		            Cipher cipher = Cipher.getInstance(algorithmStr);// algorithmStr
		            byte[] byteContent = content.getBytes("utf-8");
		            cipher.init(Cipher.ENCRYPT_MODE, key);// ʼ
		            byte[] result = cipher.doFinal(byteContent);
		            return result; //
		        }
		        catch (NoSuchAlgorithmException e)
		        {
		            e.printStackTrace();
		        }
		        catch (NoSuchPaddingException e)
		        {
		            e.printStackTrace();
		        }
		        catch (InvalidKeyException e)
		        {
		            e.printStackTrace();
		        }
		        catch (UnsupportedEncodingException e)
		        {
		            e.printStackTrace();
		        }
		        catch (IllegalBlockSizeException e)
		        {
		            e.printStackTrace();
		        }
		        catch (BadPaddingException e)
		        {
		            e.printStackTrace();
		        }
		        return null;
		    }
		    private byte[] decrypt(byte[] content, String password)
		    {
		        try
		        {  if(content==null){return null;}
		            byte[] keyStr = getKey(password);
		            SecretKeySpec key = new SecretKeySpec(keyStr, "AES");
		            Cipher cipher = Cipher.getInstance(algorithmStr);// algorithmStr
		            cipher.init(Cipher.DECRYPT_MODE, key);// ʼ
		            byte[] result = cipher.doFinal(content);
		            return result; //
		        }
		        catch (NoSuchAlgorithmException e)
		        {
		            e.printStackTrace();
		        }
		        catch (NoSuchPaddingException e)
		        {
		            e.printStackTrace();
		        }
		        catch (InvalidKeyException e)
		        {
		            e.printStackTrace();
		        }
		        catch (IllegalBlockSizeException e)
		        {
		            e.printStackTrace();
		        }
		        catch (BadPaddingException e)
		        {
		            e.printStackTrace();
		        }
		        return null;
		    }

		    private byte[] getKey(String password)
		    {
		        byte[] rByte = null;
		        if (password != null)
		        {
		            rByte = password.getBytes();
		        }
		        else
		        {
		            rByte = new byte[24];
		        }
		        return rByte;
		    }

		    /**
		     * 将二进制转换成16进制
		     * @param buf
		     * @return
		     */
		    public String parseByte2HexStr(byte buf[])
		    {
		        StringBuffer sb = new StringBuffer();
		        for (int i = 0; i < buf.length; i++)
		        {
		            String hex = Integer.toHexString(buf[i] & 0xFF);
		            if (hex.length() == 1)
		            {
		                hex = '0' + hex;
		            }
		            sb.append(hex.toUpperCase());
		        }
		        return sb.toString();
		    }

		    /**
		     * 将16进制转换为二进制
		     * @param hexStr
		     * @return
		     */
		    public byte[] parseHexStr2Byte(String hexStr)
		    {
		        if (hexStr.length() < 1)
		            return null;
		        byte[] result = new byte[hexStr.length() / 2];
		        for (int i = 0; i < hexStr.length() / 2; i++)
		        {
		            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
		            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
		            result[i] = (byte)(high * 16 + low);
		        }
		        return result;
		    }

		    // 注意: 这里的password(秘钥必须是16位的)
		    private static final String keyBytes = "beijingsolutionc";

		  /**
		   * 描述:加密 </br>
		   * 开发人员：chixin</br>
		   * 创建时间：2016-11-13</br>
		   * @param content  原始数据
		   * @return 返回加密数据
		   */
		    public String encode(String content)
		    {
		        // 加密之后的字节数组,转成16进制的字符串形式输出
		        return parseByte2HexStr(encrypt(content, keyBytes));
		    }
		    /**
		     * 描述: 解密</br>
		     * 开发人员：chixin</br>
		     * 创建时间：2016-11-13</br>
		     * @param content  加密数据
		     * @return 返回解密后的数据
		     */
		    public String decode(String content)
		    {
		        // 解密之前,先将输入的字符串按照16进制转成二进制的字节数组,作为待解密的内容输入
		        byte[] b = decrypt(parseHexStr2Byte(content), keyBytes);
		        return b==null?"":new String(b);
		    }
	}
}
