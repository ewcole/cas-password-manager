/*
 * The author licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package edu.sunyjcc.cas.authentication;

import java.util.List;

import org.jasig.cas.authentication.PasswordPolicyEnforcer;
import org.jasig.cas.authentication.LdapPasswordPolicyEnforcementException;
/**
 * Fetch the account status from multiple LDAP servers and harmonize them
 *
 * @author Ed Cole
 */
public class ListPasswordPolicyEnforcer implements PasswordPolicyEnforcer {

    /** 
     *  A list of PasswordPolicyEnforcers; expiration date will be the 
     *    earliest date for the person in each of the servers he appears in.
     */
    private List<PasswordPolicyEnforcer> enforcers;

    /**
     * @param userId The unique ID of the user
     * @return Number of days to the expiration date, or -1 if checks pass.
     */
    @Override
    public long getNumberOfDaysToPasswordExpirationDate(final String userId) throws LdapPasswordPolicyEnforcementException {
        long expDays = 1000;
        for (PasswordPolicyEnforcer enforcer : enforcers) {
            long thisExpDays = enforcer.getNumberOfDaysToPasswordExpirationDate(userId);
            if (thisExpDays > 0 && thisExpDays < expDays) {
                expDays = thisExpDays;
            }
        }
        return (expDays==1000) ? -1 : expDays;
    }

    /** Zero-argument contructor so we can initialize it as a bean. */
    public ListPasswordPolicyEnforcer() {}

    public List<PasswordPolicyEnforcer> getEnforcers() {
        return enforcers;
    }

    public void setEnforcers(List<PasswordPolicyEnforcer> enforcers) {
        this.enforcers = enforcers;
    }
}
