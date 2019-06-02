/*
  Copyright 2019 Sharon Dvir

  Unless authorized beforehand and in writting by the author,
  this program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWORD

#include <fstream>
#include <chrono>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include "common-raii/common-raii.h"

using namespace std;
using namespace commonRaii;

gpgme_key_t find_unique_key(gpgme_ctx_raii& ctx, string fpr)//TODO: move to commonRaii
{
  gpgme_key_t key;
  if (auto err{ gpgme_get_key(ctx.get(), fpr.c_str(), &key, 0)}; err != GPG_ERR_NO_ERROR)
    throw runtime_error("Can't query for key "s + fpr + " "s + string{gpgme_strerror(err)});
  return key;
}

bool validate_string_signed( pam_handle_t *pamh, gpgme_ctx_raii& ctx, const string& text, const string& sig, const string& key_str)//TODO: move to commonRaii
{
  gpgme_data_raii data_sig{sig}, data_plain{};//throws on error
  keyRaii key;


  pam_syslog(pamh, LOG_WARNING, string{text + " : " + sig}.c_str());
  key.get() = find_unique_key(ctx, key_str); //TODO: add set() to keyRaii
  if (auto err{gpgme_op_verify (ctx.get(), data_sig.get(), nullptr, data_plain.get())}; err != GPG_ERR_NO_ERROR)
    {
      pam_syslog(pamh, LOG_WARNING, string{"Verification failed "s + gpgme_strerror(err)}.c_str());
      return false;
    }
  
  constexpr int buffsize{500};//TODO: extract to func
  char buf[buffsize + 1] = "";
  int ret = gpgme_data_seek (data_plain.get(), 0, SEEK_SET);
  string plainFromSig{};
  while ((ret = gpgme_data_read (data_plain.get(), buf, buffsize)) > 0)
    {
      buf[ret] = '\0';
      plainFromSig += string{buf};
    }
  
  auto res{gpgme_op_verify_result(ctx.get())};
  if (!res)
    {
      pam_syslog(pamh, LOG_WARNING, "gpgme_op_verify_result() returned nullptr");
      return false;
    }
  for (auto s{res->signatures}; s; s = s->next)
    {
      pam_syslog(pamh, LOG_WARNING, string{"IN FOR: "s + string{key.get()->fpr + " "s +string{s->fpr} }}.c_str());
      if ((s->summary & GPGME_SIGSUM_VALID) &&
	  string{key.get()->fpr}.find(string{s->fpr}) != string::npos  &&
	  plainFromSig == text)
	return true;
    }
  return false;
}

/*
  main event.
  validate that the user is able to provide an agreed upon file via USB dongle,
  signed by a key that was preconfigured.
*/
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
#ifdef HAVE_PAM_FAIL_DELAY
  pam_fail_delay (pamh, 2'000'000);
#endif /* HAVE_PAM_FAIL_DELAY */

  constexpr auto maxUsernameSize = 100;
  const char *userChar[maxUsernameSize]{nullptr};

  //get user name, or fail
  if (pam_get_user(pamh, userChar, nullptr)!=PAM_SUCCESS || !userChar || !*userChar)
    {
      pam_syslog(pamh, LOG_WARNING, "pam_get_user() failed");
      return PAM_USER_UNKNOWN;
    }
  string user{*userChar, maxUsernameSize - 1};

  //get homedir, or fail
  auto userPw(getpwnam(user.c_str()));
  if (!userPw)
    {
      pam_syslog(pamh, LOG_WARNING, "can't get homedir of pam user");
      return  PAM_AUTHINFO_UNAVAIL;
    }
  string homeDir{userPw->pw_dir};
  //drop privilleges, or fail
  privDropper priv{pamh, userPw};
  
  auto gpHomeCstr{pam_getenv(pamh, "GNUPGHOME")};
  string gnupgHome{gpHomeCstr?gpHomeCstr:".gnupg"s};
  gpgme_ctx_raii ctx{homeDir+"/"s+gnupgHome};
  //TODO: read from config
  string trustedFprt{"9F15E1BA23DDB0B96CECE7A8D8455CE990619303"s};
  string sigPath{"/media/sharon/technician/sig"s};
  string currentPath{"/home/sharon/.lastresort_rollingstate"s};
  string machineId{"devmachine1"s};
  string nextNonce{getNonce(10)};
  string nextRotate{machineId + " "s + nextNonce};
  //keep curr open to avoid reentrant fs races.
  fstream curr{currentPath, ios::in | ios::out};//TODO: check curr.good(),is_open()
  string currStr{};//TODO: bulky. use >>

  getline(curr, currStr);
  curr.clear();
  curr.seekp(0);

  if (flags & PAM_SILENT)
    {
      pam_syslog(pamh, LOG_WARNING, "can't operate in silent mode");
      return PAM_IGNORE;
    }
  
  string clearMsg{R"(Please insert USB drive with SIGFILE.
Containing signature of the following by FPRT.
)" + currStr +"\nUpon success SIGFILE will be overwritten with: "s + nextRotate + "\n"};
  
  auto response{converse(pamh, clearMsg)};

  ifstream sigStream{sigPath};//TODO: check sigStream.good(),is_open()
  stringstream buffer;
  buffer << sigStream.rdbuf();
  sigStream.close();

  if (validate_string_signed(pamh, ctx, currStr, buffer.str(), trustedFprt))
    {
      //let the user keep a copy of the next sign requirment
      ofstream sigOvrwrt{sigPath};//TODO: check sigOvrwrt.good(),is_open()
      sigOvrwrt << nextRotate << endl;
      //update the module's next sign requirement
      curr << nextRotate << endl;
      return PAM_SUCCESS;
    }

 return PAM_AUTH_ERR;
}


PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_acct_mgmt( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_open_session( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_close_session( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_chauthtok( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
  return PAM_IGNORE;
}
