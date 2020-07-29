package com.portal.controller;

import java.net.URLDecoder;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonView;
import com.portal.encryption.PBKDF2PasswordEncryptor;
import com.portal.entity.DateUtil;
import com.portal.entity.EntityStatus;
import com.portal.entity.Result;
import com.portal.entity.SystemConstant;
import com.portal.entity.Views;
import com.portal.entity.mobileuser;
import com.portal.entity.user;
import com.portal.service.MailService;
import com.portal.service.MobileUserService;
import com.portal.service.UserService;

import javassist.NotFoundException;

@RestController
@RequestMapping("user")
public class RegistrationController extends AbstractController {

	@Autowired
	private MobileUserService mobileUserService;

	@Autowired
	private MailService mailService;

	//@Autowired
	//private UserService userService;

	private static Logger logger = Logger.getLogger(RegistrationController.class);

	private String decode(@RequestParam String newPassword) {
		try {
			newPassword = URLDecoder.decode(newPassword, "UTF-8");
		} catch (Exception e) {

		}
		return newPassword;
	}

	public String oldhash(String encrypt) {
		byte[] decoded = Base64.decodeBase64(encrypt);
		String hexString = Hex.encodeHexString(decoded);
		String salt = hexString.substring(16, 32);
		String hash = hexString.substring(32, hexString.length());
		/*
		 * byte[] hexSecrectDecode; String saltbase64 = ""; String secrectbase64 = "";
		 * try { hexSecrectDecode = Hex.decodeHex(hash.toCharArray()); secrectbase64 =
		 * DatatypeConverter.printBase64Binary(hexSecrectDecode);
		 * 
		 * byte[] hexSaltDecode = Hex.decodeHex(salt.toCharArray()); saltbase64 =
		 * DatatypeConverter.printBase64Binary(hexSaltDecode);
		 * System.out.println("saltbase64...." + saltbase64);
		 * System.out.println("secrectbase64....."+secrectbase64);
		 * 
		 * } catch (DecoderException e) { logger.error("Error: " + e); }
		 */

		return "PBKDF2_" + "160_" + "128000_" + salt + "_" + hash;
	}

	public String encryptPassword(String password) throws Exception {
		PBKDF2PasswordEncryptor pbkdf2PasswordEncryptor = new PBKDF2PasswordEncryptor();
		String result = pbkdf2PasswordEncryptor.doEncrypt(PBKDF2PasswordEncryptor.DEFAULT_ALGORITHM, password, "");
		String[] results = result.split("_");

		byte[] saltdecoded = Base64.decodeBase64(results[2]);
		String hexSaltString = Hex.encodeHexString(saltdecoded);
		byte[] secretdecoded = Base64.decodeBase64(results[3]);
		String hexSecretString = Hex.encodeHexString(secretdecoded);
		String hexstring = "000000a0" + "0001f400" + hexSaltString + hexSecretString;
		String encodedbase64 = "";

		byte[] decString = Hex.decodeHex(hexstring.toCharArray());
		encodedbase64 = DatatypeConverter.printBase64Binary(decString);
		return encodedbase64;
	}

	@PostMapping("encrypt")
	public String encrypt(@RequestParam String userpassword) throws Exception {
		return encryptPassword(userpassword);
	}

	private boolean validatePassword(String password, String hash) throws NotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
		if (hash != null) {
			hash = decode(hash);
		}

		password = decode(password);
		if (hash != null) {
			return mobileUserService.validatePassword(password, hash);
		}
		throw new NotFoundException("The endpoint you requested is not available for the given attributes");
	}

	private boolean isValid(JSONObject json, JSONObject resultJson) {
		Object password = json.get("password");
		Object email = json.get("email");

		if (password.toString().isEmpty() || password == null) {
			resultJson.put("message", "Empty Password!");
			resultJson.put("status", "0");
			return false;
		}

		if (email.toString().isEmpty() || email == null) {
			resultJson.put("message", "Empty Email and Phone!");
			resultJson.put("status", "0");
			return false;
		}

		return true;
	}

	private mobileuser parseMobileUser(JSONObject json) throws Exception {
		mobileuser mobileUser = new mobileuser();
		mobileUser.setUserid(SystemConstant.BOID_REQUIRED);
		mobileUser.setName(json.get("name").toString());
		mobileUser.setScreenname(json.get("screenname").toString());
		mobileUser.setEmailaddress(json.get("email").toString());
		mobileUser.setAndroidid(json.get("deviceid").toString());
		mobileUser.setPhoneno(json.get("phoneno").toString());
		mobileUser.setJobtitle(json.get("jobtitle").toString());
		mobileUser.setStatus(EntityStatus.ACTIVE);
		mobileUser.setCreatedate(new Date());

		String password = json.get("password").toString();
		String encryptedPassword = encryptPassword(password);
		mobileUser.setPassword(encryptedPassword);
		mobileUser.setReminderqueryanswer(json.get("reminderqueryanswer").toString());
		mobileUser.setReminderqueryquestion(json.get("reminderqueryquestion").toString());
		return mobileUser;
	}

	/*
	 * request :{ "password":"april12345", "screenname":"April",
	 * "emailaddress":"April@gmail.com", "name":"April Than Naing",
	 * "jobtitle":"Java Developer", "androidid":4579435345, "phoneno":"0945683475",
	 * "reminderqueryanswer": "What is your father's last name?",
	 * "reminderqueryquestion": "aung" }
	 * 
	 */

	@RequestMapping(value = "save", method = RequestMethod.POST)
	@ResponseBody
	@JsonView(Views.Summary.class)
	public JSONObject registration(@RequestBody JSONObject json) throws Exception {
		JSONObject resultJson = new JSONObject();
		mobileuser mobileuser = mobileUserService.getUserByEmail(json.get("email").toString().trim());
		if (mobileuser != null) {
			resultJson.put("message", "Existing Email is invalid!");
			resultJson.put("status", "0");
			return resultJson;
		}

		mobileuser user = parseMobileUser(json);
		mobileUserService.saveUser(user);
		resultJson.put("status", "1");
		resultJson.put("userId", user.getUserid());
		return resultJson;
	}

	/*
	 * { "email":"April@gmail.com", "password":"123" }
	 */
	@RequestMapping(value = "login", method = RequestMethod.POST)
	@ResponseBody
	@JsonView(Views.Summary.class)
	public JSONObject logIn(@RequestBody JSONObject json) throws Exception {
		JSONObject resultJson = new JSONObject();
		if (isValid(json, resultJson)) {
			String email = json.get("email").toString();
			String password = json.get("password").toString();
			mobileuser user = mobileUserService.getUserByEmail(email);
			Object phoneno = json.get("phoneno");

			if (user == null && phoneno != null)
				user = mobileUserService.getUserByPhone(phoneno.toString().trim());

			if (user == null) {
				resultJson.put("message", "Email is not valid!");
				resultJson.put("status", "0");
			}

			if (user != null) {
				String encryptedPassword = user.getPassword();
				if (validatePassword(password, oldhash(encryptedPassword))) {
					resultJson.put("status", "1");
					resultJson.put("user", user);
					resultJson.put("message", "Login Success!");
					return resultJson;
				}

				resultJson.put("message", "Wrong password. Try again or click Forgot password to reset it!");
				resultJson.put("status", "0");
			}
		}
		return resultJson;
	}

	private String getFullName(user user) {
		return user.getFirstname() != null ? user.getFirstname() : "" + " " + user.getMiddlename() != null ? user.getMiddlename() : "" + user.getLastname() != null ? user.getLastname() : "";
	}

	private mobileuser parseMobileUser(user user) {
		mobileuser mobileUser = new mobileuser();
		mobileUser.setUserid(SystemConstant.BOID_REQUIRED);
		mobileUser.setName(getFullName(user));
		mobileUser.setScreenname(user.getScreenname());
		mobileUser.setEmailaddress(user.getEmailaddress());
		mobileUser.setJobtitle(user.getJobtitle());
		mobileUser.setStatus(EntityStatus.ACTIVE);
		mobileUser.setCreatedate(DateUtil.parseDate(user.getCreatedate()));
		mobileUser.setPasswordreset(Integer.parseInt(user.getPasswordreset()));
		mobileUser.setPassword(user.getPassword_());
		mobileUser.setFacebookid(user.getFacebookid());
		mobileUser.setReminderqueryanswer(user.getReminderqueryanswer());
		mobileUser.setReminderqueryquestion(user.getReminderqueryquestion());
		return mobileUser;
	}

//	@RequestMapping(value = "import", method = RequestMethod.POST)
//	@ResponseBody
//	@JsonView(Views.Summary.class)
//	public JSONObject importUsers() {
//		JSONObject resultJson = new JSONObject();
//		List<user> users = userService.getAllWebUsers();
//		users.forEach(user -> {
//			try {
//				mobileUserService.save(parseMobileUser(user));
//				resultJson.put("status", "1");
//
//			} catch (Exception e) {
//				logger.error("Error: " + e);
//				resultJson.put("status", "0");
//				return;
//			}
//		});
//		return resultJson;
//	}

	@RequestMapping(value = "update", method = RequestMethod.POST)
	@ResponseBody
	@JsonView(Views.Summary.class)
	public JSONObject registration(@RequestBody mobileuser reqUser) throws Exception {
		JSONObject resultJson = new JSONObject();
		Result res = new Result();
		mobileuser mbuser = new mobileuser();
		if (reqUser.getUserid() != 0) {
			mbuser.setUserid(0);
			mbuser = mobileUserService.validUserid(reqUser.getUserid());
			if (mbuser.getUserid() != 0) {
				res = validationUpdate(reqUser, mbuser.getPassword());
				if (!res.getStatus().equals("0")) {
					if (!res.getPassword().equals(null) && !res.getPassword().equals("")) {
						mbuser.setPassword(res.getPassword());
						mbuser.setPasswordmodifieddate(new Date());
					}
					if (!reqUser.getScreenname().equals(null) && !reqUser.getScreenname().equals("")) {
						mbuser.setScreenname(reqUser.getScreenname());
					}
					if (!reqUser.getName().equals(null) && !reqUser.getName().equals("")) {
						mbuser.setName(reqUser.getName());
					}
					if (!reqUser.getJobtitle().equals(null) && !reqUser.getJobtitle().equals("")) {
						mbuser.setJobtitle(reqUser.getJobtitle());
					}
					if (!reqUser.getPhoneno().equals(null) && !reqUser.getPhoneno().equals("")) {
						mbuser.setPhoneno(reqUser.getPhoneno());
					}

					res = mobileUserService.update(mbuser);
					res.setStatus("1");
				}
			}
		} else {
			res.setDescription("User is not found");
			res.setStatus("0");
		}
		resultJson.put("status", res.getStatus());
		resultJson.put("message", res.getDescription());
		return resultJson;
	}

	public Result validationUpdate(mobileuser req, String oldpassword) throws Exception {
		Result res = new Result();
		if (!req.getPassword().equals("")) {
			if (!req.getNewpassword1().equals("")) {
				if (!req.getPassword().equals(req.getNewpassword1())) {
					if (!req.getNewpassword2().equals("")) {
						if (!req.getNewpassword1().equals(req.getNewpassword2())) {
							res.setDescription("Your new password must be same with your re enter password");
							res.setStatus("0");
						} else {
							if (validatePassword(req.getPassword(), oldhash(oldpassword))) {
								String encryptedPassword = encryptPassword(req.getNewpassword1());
								res.setPassword(encryptedPassword);
								res.setStatus("1");
							} else {
								res.setStatus("0");
								res.setDescription("Please enter correct current password");
							}
						}
					} else {
						res.setStatus("0");
						res.setDescription("Please enter the same new password again.");
					}
				} else {
					res.setStatus("0");
					res.setDescription("Your new password cannot be the same as your old password. Please enter a different password.");
				}
			} else {
				res.setStatus("0");
				res.setDescription("Please enter new password");
			}
			return res;
		} else {
			if (req.getNewpassword1().equals("") && req.getNewpassword2().equals("")) {
				res.setStatus("1");
				res.setPassword("");
			} else {
				res.setStatus("0");
				res.setDescription("Please enter your current password");
			}
			return res;
		}
	}

	public static String getRandomNumberString() {
		Random rnd = new Random();
		int number = rnd.nextInt(999999);
		return String.format("%06d", number);
	}

	@PostMapping("validate")
	public Boolean validate(@RequestParam String userpassword, @RequestParam(required = false) String encrypt) throws Exception {
		return validatePassword(userpassword, oldhash(encrypt));
	}

	private JSONObject register(JSONObject json) {
		JSONObject resultJson = new JSONObject();
		Object object = json.get("email");
		String email = object.toString();
		mobileuser user = mobileUserService.getUserByEmail(email);
		if (user != null) {
			resultJson.put("status", "0");
			resultJson.put("message", "Email is already registered!");
			return resultJson;
		}

		String code = getRandomNumberString();
		try {
			mailService.sendMail(email, "Password Rest Code ", "Password Rest Code: " + code);
		} catch (Exception e) {
			resultJson.put("message", "Can't send mail");
			resultJson.put("status", "0");
			return resultJson;
		}

		String[] questions = new String[] { "what-is-your-library-card-number", "what-is-your-father's  middle name", "what-was-your-first-teacher's-name", "what-was-your-first-phone-number", "What is your M-Unit and BC Number", "What is your name?", "what is you ministry", "What\'s childhood name?", "What was your favourite colour?", "What is your first year roll no?" };
		resultJson.put("questions", questions);
		resultJson.put("code", code);
		resultJson.put("message", "success");
		resultJson.put("status", "1");
		return resultJson;
	}

	/*
	 * request - email, response - code and questions
	 * 
	 * 
	 * { "email":"April@gmail.com", "type":"register" }
	 * 
	 * { "email":"April@gmail.com", "type":"forget" }
	 */
	@RequestMapping(value = "code", method = RequestMethod.POST)
	@ResponseBody
	@JsonView(Views.Summary.class)
	public JSONObject getQuestions(@RequestBody JSONObject json) throws Exception {
		String type = json.get("type").toString();
		switch (type) {
		case "register":
			return register(json);
		case "forget":
			return forgetPassword(json);
		default:
			return null;
		}
	}

	private JSONObject forgetPassword(@RequestBody JSONObject json) throws Exception {
		JSONObject resultJson = new JSONObject();
		String code = getRandomNumberString();

		Object object = json.get("email");
		if (object == null) {
			resultJson.put("status", "0");
			resultJson.put("message", "Email is not valid!");
			return resultJson;
		}

		String email = object.toString();
		mobileuser user = mobileUserService.getUserByEmail(email);
		if (user == null) {
			resultJson.put("status", "0");
			resultJson.put("message", "Email is not existing!");
			return resultJson;
		}

		try {
			mailService.sendMail(email, "Password Rest Code ", "Password Rest Code: " + code);
		} catch (Exception e) {
			logger.error("Error: " + e);
			resultJson.put("status", "0");
			resultJson.put("message", "Can't send mail!");
			return resultJson;
		}
		List<String> questions = new ArrayList<String>();
		questions.add(user.getReminderqueryquestion() != null ? user.getReminderqueryquestion() : "");
		resultJson.put("questions", questions);
		resultJson.put("answer", user.getReminderqueryanswer() != null ? user.getReminderqueryanswer() : "");
		resultJson.put("code", code);
		resultJson.put("status", "1");
		resultJson.put("message", "Success!");
		resultJson.put("userid", user.getUserid());
		return resultJson;
	}

	/*
	 * { "userId":"1935", "password":"april12345" }
	 */
	@RequestMapping(value = "resetpassword", method = RequestMethod.POST)
	@ResponseBody
	@JsonView(Views.Summary.class)
	public JSONObject resetPassword(@RequestBody JSONObject json) throws Exception {
		JSONObject resultJson = new JSONObject();
		Object userId = json.get("userId");
		if (userId == null) {
			resultJson.put("status", "0");
			resultJson.put("message", "Empty User!");
		}

		Object password = json.get("password");
		if (password == null || password.toString().isEmpty()) {
			resultJson.put("status", "0");
			resultJson.put("message", "Invalid password!");
		}

		mobileuser user = mobileUserService.getUserByUserId(Long.parseLong(userId.toString()));
		if (user == null) {
			resultJson.put("status", "0");
			resultJson.put("message", "Invalid User!");
		}

		user.setPasswordreset(1);
		user.setPassword(encryptPassword(password.toString()).trim());
		mobileUserService.saveUser(user);
		resultJson.put("status", "1");
		resultJson.put("message", "Success!");
		return resultJson;
	}

}
