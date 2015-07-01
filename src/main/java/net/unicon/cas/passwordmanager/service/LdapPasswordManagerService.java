package net.unicon.cas.passwordmanager.service;

import java.util.List;

import javax.validation.constraints.Size;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import net.unicon.cas.passwordmanager.UserLockedOutException;
import net.unicon.cas.passwordmanager.ldap.LdapServer;
import net.unicon.cas.passwordmanager.flow.SecurityChallenge;
import org.springframework.ldap.AuthenticationException;
import org.springframework.ldap.NameNotFoundException;
import org.springframework.ldap.core.ObjectRetrievalException;

/**
 * <p>LDAP implementation of a PasswordManagerService.</p>
 * @author Drew Mazurek &lt;dmazurek@unicon.net&gt;
 *
 */
public class LdapPasswordManagerService implements PasswordManagerService {

	private final Log logger = LogFactory.getLog(this.getClass());
	@Size(min=1)
	private List<LdapServer> ldapServers;
	private PasswordManagerLockoutService lockoutService;

	@Override
	public SecurityChallenge getUserSecurityChallenge(String username) {
                LdapServer lastServer = null;
		for(LdapServer server : ldapServers) {
			try {
                            logger.debug("Looking for security challenge for " + username + " at " + server.getDescription());
				SecurityChallenge challenge = server.getUserSecurityChallenge(username);
				// Ed Cole 2015-06-30 - Only return the challenge if it is not null.
                                //    There might be a valid one in another server.
				if(logger.isDebugEnabled()) {
					if(challenge != null) {
						logger.debug("Successfully got security challenge for " + username + " at " + server.getDescription());
					} else {
						logger.debug("Got null security challenge for " + username + " at " + server.getDescription());
					}
				}
                                if (challenge != null) {
                                    return challenge;
                                }
                                lastServer = server;
			} catch(NameNotFoundException ex) {
				logger.debug("Didn't find " + username + " in " + server.getDescription());
				// ignore it... try the next server
			} catch(ObjectRetrievalException ex) {
				logger.debug("Multiple results found for " + username);
				// ignore it... try the next server
			}
		}
		if (lastServer == null) {
                    throw new NameNotFoundException("Couldn't find username " 
				+ username + " in any of provided servers.");
                }
                return null;
	}

	@Override
	public void setUserSecurityChallenge(String username,
			SecurityChallenge securityChallenge) {
                // Manually track whether we set the name or not.
                boolean nameChanged = false;
		for(LdapServer server : ldapServers) {
			try {
				logger.debug("Attempting to set user security challenge for " + username + " at " + server.getDescription());
				server.setUserSecurityChallenge(username, securityChallenge);
				logger.debug("Successfully set user security challenge for " + username + " at " + server.getDescription());
                                // - Ed Cole - 2015-06-29 - Don't quit after 
                                //   changing the first security question; copy 
                                //    it to all of the LDAP servers.
				// return;
                                nameChanged = true;
			} catch(NameNotFoundException ex) {
				logger.debug("Didn't find " + username + " in " + server.getDescription());
				// ignore it... try the next server
			} catch(ObjectRetrievalException ex) {
				logger.debug("Multiple results found for " + username);
				// ignore it... try the next server
			}
		}
		if (!nameChanged) {
                	throw new NameNotFoundException("Couldn't find username " 
				+ username + " in any of provided servers.");
                } 
	}
	
	public SecurityChallenge getDefaultSecurityChallenge(String username) {
		
		for(LdapServer ldapServer : ldapServers) {
			try {
				SecurityChallenge challenge = ldapServer.getDefaultSecurityChallenge(username);
				if(logger.isDebugEnabled()) {
					if(challenge != null) {
						logger.debug("Successfully got default security challenge for " + username + " at " + ldapServer.getDescription());
					} else {
						logger.debug("Got null default security challenge for " + username + " at " + ldapServer.getDescription());
					}
				}
				return challenge;
			} catch(NameNotFoundException ex) {
				logger.debug("Didn't find " + username + " in " + ldapServer.getDescription());
				// ignore... we'll try another server
			} catch(ObjectRetrievalException ex) {
				logger.debug("Multiple results found for " + username);
				// ignore it... try the next server
			}
		}
		
		logger.debug("Couldn't find default security questions for " + username);
		throw new NameNotFoundException("Couldn't find username " 
				+ username + " in any of provided servers.");
	}

	@Override
	public void setUserPassword(String username, String password) {
		logger.debug("We have " + ldapServers.size() + " LDAP servers to look at.");

                boolean passwordChanged = false;
		for(LdapServer ldapServer : ldapServers) {
			logger.debug("Checking server " + ldapServer.getDescription() + " for user " + username);
			try {
				ldapServer.setPassword(username, password);
				logger.debug("Successfully set password for " + username + " at " + ldapServer.getDescription());
				passwordChanged = true;
			} catch(NameNotFoundException ex) {
				logger.debug("Didn't find " + username + " in " + ldapServer.getDescription());
				// ignore... we'll try another server
			} catch(ObjectRetrievalException ex) {
				logger.debug("Multiple results found for " + username);
				// ignore it... try the next server
			}
		}
		if (!passwordChanged) {
                    logger.debug("Couldn't find server for " + username);
                    throw new NameNotFoundException("Couldn't find username " 
				+ username + " in any of provided servers.");
		}
	}

	@Override
	public void changeUserPassword(String username, String oldPassword, String newPassword) throws UserLockedOutException {
		
		// throws UserLockedOutException if this isn't allowed
		lockoutService.allowAttempt(username);
		
                boolean oldPasswordIsValid = false;
                for(LdapServer ldapServer : ldapServers) {
                    logger.debug("Checking old password for " + username + " against " + ldapServer.getDescription());
                    try {
                        if(ldapServer.verifyPassword(username, oldPassword)) {
                            oldPasswordIsValid = true;
                            logger.debug("Authenticated against " + ldapServer.getDescription());
                            lockoutService.clearIncorrectAttempts(username);
                            break; // You've found what you want; don't keep looking.
                        }
                    } catch(AuthenticationException ex) {
                        logger.debug("Didn't find " + username + " in " + ldapServer.getDescription());
                        // ignore... we'll try another server
                    } catch(NameNotFoundException ex) {
                        logger.debug("Didn't find " + username + " in " + ldapServer.getDescription());
                        // ignore... we'll try another server
                    } catch(ObjectRetrievalException ex) {
                        logger.debug("Multiple results found for " + username);
                        // ignore it... try the next server
                    }
                }
                if (oldPasswordIsValid) {
                    // We found a server with a valid password match, so go ahead and change them all.
                    for(LdapServer ldapServer : ldapServers) {
			try {
				ldapServer.setPassword(username, newPassword);
				logger.debug("Successfully changed password for " + username + " at " + ldapServer.getDescription());
			} catch(AuthenticationException ex) {
				logger.debug("Didn't find " + username + " in " + ldapServer.getDescription());
				// ignore... we'll try another server
			} catch(NameNotFoundException ex) {
				logger.debug("Didn't find " + username + " in " + ldapServer.getDescription());
				// ignore... we'll try another server
			} catch(ObjectRetrievalException ex) {
				logger.debug("Multiple results found for " + username);
				// ignore it... try the next server
			}
                    }
                } else {
                    lockoutService.registerIncorrectAttempt(username);
                    logger.debug("Couldn't find server for " + username + " or bad password.");
                    throw new NameNotFoundException("Couldn't find username " 
				+ username + " in any of provided servers or bad password.");	
                }
	}

	public void setLdapServers(List<LdapServer> ldapServers) {
		this.ldapServers = ldapServers;
	}

	public void setLockoutService(PasswordManagerLockoutService lockoutService) {
		this.lockoutService = lockoutService;
	}
}
