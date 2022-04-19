package com.example.demo.userservice;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.model.Otp;
import com.example.demo.model.User;
import com.example.demo.model.Verifier;
import com.example.demo.repo.OtpRepository;
import com.example.demo.repo.UserRepository;

@Service
public class UserServiceImp implements UserService,UserDetailsService {

	@Autowired
	private UserRepository userReopsitory;
	@Autowired
	private OtpRepository otpRepository;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@Override

	public String register(User us1) {

		if (!(us1.getFirstName().isEmpty()) && !(us1.getLastName().isEmpty()) && !(us1.getEmailId().isEmpty())
				&& !(us1.getUserName().isEmpty()) && !(us1.getPassWord().isEmpty())) {
			if (us1.getFirstName().matches("^[a-zA-Z]*$")) {
				if (us1.getLastName().matches("^[a-zA-Z]*$")) {
					Pattern p1 = Pattern.compile(
							"^(?=.*[0-9])" + "(?=.*[a-z])(?=.*[A-Z])" + "(?=.*[@#$%^&+=])" + "(?=\\S+$).{8,20}$");
					Matcher m1 = p1.matcher(us1.getPassWord());

					if (m1.find()) {
						Pattern p = Pattern.compile("[a-zA-Z][a-zA-Z0-9-.]*@[a-zA-Z0-9]+([.][a-zA-Z]+)+");
						Matcher m = p.matcher(us1.getEmailId());

						if (m.find()) {

							User dataBaseUser1 = userReopsitory.findByUserName(us1.getUserName());

							if (dataBaseUser1 != null)
								return "username already exists!!!!";

							User dataBaseUser2 = userReopsitory.findByEmailId(us1.getEmailId());

							if (dataBaseUser2 != null)
								return "Emailid  already exists!!!!";

							String encodedPassword = bCryptPasswordEncoder.encode(us1.getPassWord());
							us1.setPassWord(encodedPassword);
							
							
							String otp=otpGeneration();
		
							mail(us1.getEmailId(),otp,us1.getFirstName());
							
							userReopsitory.save(us1);
							
							Otp otpObject=new Otp();
							
							otpObject.setUserName(us1.getUserName());
							otpObject.setOtp(otp);
							
							
							otpRepository.save(otpObject);
							

							String s1 = " User added successfully and otp is send to your email id";
							return s1;

						} else {
							return "not valid email id";
						}

					} else {
						return "Password must contain one uppercase,one lowercase, one special character(@#$%^&+=) and one digit";
					}
				} else {
					return "Last name should contain only characters";
				}
			} else {
				return "First name should contain only characters";
			}
		} else {
			return "please fill all the field";
		}

	}

	private String otpGeneration() {
		
		
		 int leftLimit = 48; // numeral '0'
		    int rightLimit = 122; // letter 'z'
		    int targetStringLength = 10;
		    Random random = new Random();

		    String generatedString = random.ints(leftLimit, rightLimit + 1)
		      .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
		      .limit(targetStringLength)
		      .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
		      .toString();
		    
		    return generatedString;
	}

	private void mail(String emailId, String otp, String firstName) {
		String host="smtp.gmail.com";
		
		// get system properties
		
		Properties properties = System.getProperties();
		
		properties.put("mail.smtp.host", host);
		
		properties.put("mail.smtp.port", "465");
		
		properties.put("mail.smtp.ssl.enable", "true");
		
		properties.put("mail.smtp.auth", "true");
		
		properties.put("mail.smtp.starttls.enable","true"); 
		
		
		properties.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
		// step 1: to get session object
		
		Session session = Session.getInstance(properties, new Authenticator() {

			@Override
			protected PasswordAuthentication getPasswordAuthentication() {
				
				
				return new PasswordAuthentication("biz4solutions.sagar@gmail.com", "igashqxfbdvuspqz"); 
			}
			
			 
		});
		
		
		// step 2 : compose message
		
		MimeMessage m1 = new MimeMessage(session);
		try {
			m1.setFrom(new InternetAddress("biz4solutions.sagar@gmail.com"));
			
			
			m1.addRecipient(Message.RecipientType.TO, new InternetAddress(emailId));
			
			
			
			m1.setSubject("Registration to digilearn");
			
			
			m1.setText("Dear "+firstName+"\nwelcome to digilearn.....\nYour OTP is  "+otp);
			
		//step 3 : send message using Transport class
			
			Transport.send(m1);
			
		}
		catch (Exception e) {
			
			e.printStackTrace();
			
		}
		
		
		
	}

	@Override
	public String login(User us) {
		
		
		Otp otpdatabase=otpRepository.findByUserName(us.getUserName());
		
		if(otpdatabase.isVerified()==false)
			return "Your account is not verified, please verify first then login";

		if (!(us.getUserName().isBlank()) && !(us.getPassWord().isBlank()))
		{
			
			
		
			
				User dataBaseUser = userReopsitory.findByUserName(us.getUserName());

				if (dataBaseUser != null)
				{
					if (bCryptPasswordEncoder.matches(us.getPassWord(), dataBaseUser.getPassWord()))
					{
					return "Welcome    " + dataBaseUser.getUserName();
					}
				}

				return " invalid credentials";
			
		
		}
		else
		{
			return "all field are mandatory";
		}
	}

	@Override
	public String verifyUser(Verifier verifier) {
		
		
		User dataBaseuser=userReopsitory.findByUserName(verifier.getUserName());
		
		if(dataBaseuser==null)
			return "invalid username";
		
		Otp otpEntityDatabase=otpRepository.findByUserName(verifier.getUserName());
		
		if(otpEntityDatabase.getOtp().equals(verifier.getOtp()))
		{
			otpEntityDatabase.setVerified(true);
			otpRepository.save(otpEntityDatabase);
			return "Your account is verified successfully , you are allowed to login";
		}
		return "invalid otp entered";
	}
	
	public User findByUsername(String username)
	{
		return userReopsitory.findByUserName(username);
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		User user=findByUsername(username);
		
		if(user==null)
		{
			throw new UsernameNotFoundException("user not found");
		}
		 return new org.springframework.security.core.userdetails.User(user.getUserName(), user.getPassWord(), true, true, true, true, new ArrayList<GrantedAuthority>());
		
	}
	
	

}
