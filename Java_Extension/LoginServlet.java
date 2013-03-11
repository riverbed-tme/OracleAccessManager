/******************************************************************************************************************************************

Author			: 		PREYA SHAH
ClassName		:		LoginServlet
Usage			: 		JavaExtension for Stingray and OAM (Oracle Access Manager) Integration

******************************************************************************************************************************************/


import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;
import oracle.security.am.asdk.*;
import com.zeus.ZXTMServlet.*;
import org.apache.log4j.*;

public class LoginServlet extends HttpServlet {

	static Logger log = Logger.getLogger(LoginServlet.class);

     private String authNURL = null;
     private Hashtable<String, String> primaryServer = null;
     private Hashtable<String, String> secondaryServer = null;
     private String accessServer1 = null;
     private String accessServer2 = null;
     private String accessServer1_MAX_CONNS = null;
     private String accessServer2_MAX_CONNS = null;
     private String oam_version = "OAM_11G";
     private ResourceRequest res = null;
     private AccessClient ac = null;
     private boolean flag = false;

     public AccessClient getAccessClient() {
         return ac;
     }

     public ResourceRequest getResource() {
         return res;
    }

    public void initOAMSDKProvider(String client_id, String webgate_id, String[] args) {
        Hashtable<String, Object> acConfig = new Hashtable<String, Object>();
        // "OAM_11G" "accessgate-oic" "0" "OPEN" "swimdaddy.us.oracle.com:5575" "4" "oam_server_2:5575" "4"
        if(flag)
        	log.info("inside initOAMSDKProvider");
        try {
            oam_version = args[0];
            acConfig.put(AccessClient.CFG_WEBGATE_ID, webgate_id);
            acConfig.put(AccessClient.CFG_DEBUG_VALUE, args[2]);
            acConfig.put(AccessClient.CFG_TRANSPORT_SECURITY, args[3]);
            accessServer1 = args[4];
            accessServer1_MAX_CONNS = args[5];

            if (args.length > 6) {
                acConfig.put(AccessClient.CFG_ENCRYPTED_PASSWORD, args[6]);
            }

            if (args.length > 7) {
                acConfig.put(AccessClient.CFG_PASSPHRASE, args[7]);
            }

            if (args.length > 8) {
                acConfig.put(AccessClient.CFG_KEYSTORE, args[8]);
            }

            if (args.length > 9) {
                acConfig.put(AccessClient.CFG_TRUSTSTORE, args[9]);
            }

			acConfig.put(AccessClient.CFG_ENCRYPTED_PASSWORD,"");


            if (accessServer1 != null) {
                StringTokenizer st = new StringTokenizer(accessServer1, ":");
                primaryServer = new Hashtable<String, String>();
                primaryServer.put(AccessClient.CFG_SERVER_HOST, st.nextToken());
                primaryServer.put(AccessClient.CFG_SERVER_PORT, st.nextToken());
                if (accessServer1_MAX_CONNS != null) {
                    primaryServer.put(AccessClient.CFG_SERVER_MAX_CONNS, accessServer1_MAX_CONNS);
                } else {
                    primaryServer.put(AccessClient.CFG_SERVER_MAX_CONNS, "4");
                }

                ArrayList<Hashtable<String, String>> aPrimary =
                    new ArrayList<Hashtable<String, String>>();
                aPrimary.add(primaryServer);
                acConfig.put(AccessClient.CFG_PRIMARY_SERVER_LIST, aPrimary);
            }


            if (!oam_version.equalsIgnoreCase("OAM_10G") &&
                !oam_version.equalsIgnoreCase("OAM_11G")) {
                oam_version = "OAM_11G";
            }

			if(flag)
            	log.info("oam_version = " + oam_version);

			if(flag)
				log.info("Config Object --> " + acConfig.toString());

            ac = AccessClient.createInstance(acConfig, client_id, AccessClient.CompatibilityMode.valueOf(oam_version), null);
           // ac = AccessClient.createInstance(acConfig, client_id, AccessClient.CompatibilityMode.OAM_10G, null);

			if(flag)
				log.info("AccessClient object is created");

        } catch (AccessException e) {
            System.out.println("Exception : " + e.toString());
        } catch (Throwable e) {
            System.out.println("Exception : " + e.toString());
        }
    }


   public void init(ServletConfig config) throws ServletException {

      try {
		  BasicConfigurator.configure();

		  String[] args = new String[6];

		  //Get all the parameter values defined by Stingray

		  args[0] = config.getInitParameter("oam_version");
		  args[1] = config.getInitParameter("webgate_id");
		  args[2] = config.getInitParameter("debug_value");
		  args[3] = config.getInitParameter("transport_security");
		  String primaryHost = config.getInitParameter("primary_host");
		  String primaryPort = config.getInitParameter("primary_port");
		  args[4] = primaryHost+":"+primaryPort;
		  args[5] = config.getInitParameter("max_connections");
		  String debugFlag = config.getInitParameter("debug_flag");

		  if(debugFlag.equalsIgnoreCase("On"))
		  		flag = true;
		  else
		  		flag = false;


		/*  args[0] = "OAM_10G";
		  args[1] = "AccessClient10g_4";
		  args[2] = "0";
		  args[3] = "OPEN";
		  args[4] = "WIN-H0HSFE72GKA:5575";
		  args[5] = "1"; */

		  initOAMSDKProvider("log","AccessClient10g_4",args);


      } catch (Exception ae) {
         ae.printStackTrace();
      }
   }

   public void service(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

		  AuthenticationScheme authnScheme = null;
		  UserSession user = null;
		  ResourceRequest resource = null;
		  HttpSession session = null;
		  Hashtable cred = new Hashtable();

		  //Get all the arguments passed by Stingray Traffic Script

		  String[] args = (String[])request.getAttribute( "args" );
		  String sUserName = args[0];
		  String sPassword = args[1];
		  if(flag){
			  log.info("Username =" + sUserName);
			  log.info("Password ="+ sPassword);
	      }

		  String requestedPage = args[2];
		  if(flag)
		  	log.info("requestedPage = " + args[2]);
		  String reqMethod = args[3];

		  try{
			    session = request.getSession( false);
			    if(flag)
					log.info("session="+ session);

		 }catch(Exception e){
			 System.out.println("Exception :"+e);
			 if(flag)
			 	log.info("Exception" + e);
		 }


      try {
			 if (requestedPage == null || requestedPage.length()==0) {
				return;
			 }

			 //Create ResourceRequest object with Resource Type, Resource Name and Operation
			 if(flag)
			 	log.info(" Access Client is   "+ac.toString());

			 resource = new ResourceRequest(ac,"http", requestedPage, "GET");


			 if (resource.isProtected()) {
					//Get the AuthenticationScheme for the resource
					authnScheme = new AuthenticationScheme(ac, resource);
					if(flag)
						log.info("authnscheme created");

					//Check the type of AuthenticationScheme
					if (authnScheme.isForm()) {
						if (session == null) {
						if (sUserName != null) {
								cred.put("userid", sUserName);
								cred.put("password", sPassword);

								//Create UserSession object which will Authenticate the given user credential against the requested resource
								user = new UserSession(ac,resource, cred);
								if(flag)
									log.info("user object is created");


								//Check the status of the User
								if (user.getStatus() == UserSession.LOGGEDIN) {
									if (user.isAuthorized(resource)) {

										String token = user.getSessionToken();
										if(flag)
											log.info("User Session/Cookie Value -->" + token);


										//Send the Success response to Stingray in case of user is authorized

										((ZXTMServletRequest)request).setConnectionData(sUserName,"Success");

										//Set the
										((ZXTMServletRequest)request).setData(sUserName,token);

									} else {
										if(flag)
											log.info("user is not authorized");
											//Send the Failure response to Stingray in case of user is unauthorized
										((ZXTMServletRequest)request).setConnectionData(sUserName,"Failure");

									}
								} else {
									if(flag)
										log.info("User "+ sUserName + " not logged in");

								}
							} else {
								if(flag)
									log.info("Username parameter is required");

							}
               } else {
                  user = (UserSession)session.getValue("user");
                  if (user.getStatus() == UserSession.LOGGEDIN) {

                  }
               }
            } else {
				if(flag)
			   		log.info("Resource Page" + requestedPage + " is not protected with Form");
            }
         } else {

			 if(flag)
				log.info("Page " + requestedPage + " is not protected");

         }
      } catch (AccessException ex) {
        if(flag)
          log.info("Access Exception ::" + ex);
      } catch (Exception e){
		  if(flag)
		  	log.info("Access Exception ::" + e);
	  }

   }
}