#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <vector>
#include <regex>
#include <filesystem>
#include "common-raii/common-raii.h"

extern "C" {
#include <security/pam_appl.h>
#include <gpgme.h>
#include <curl/curl.h>
}

using namespace std;
namespace fs = std::filesystem;
using namespace commonRaii;

TEST(unitTests, emptyTest)
{
  pam_handle_t *pamh;
  struct pam_conv pam_conversation;
  string module_name{"last-resort"s};
  string user_name{"sharon"s};
  ASSERT_EQ(pam_start(module_name.c_str(), user_name.c_str(), &pam_conversation, &pamh), PAM_SUCCESS);
  ASSERT_EQ(pam_authenticate(pamh, PAM_SILENT), PAM_PERM_DENIED);
  ASSERT_EQ(pam_end(pamh, PAM_SUCCESS), PAM_SUCCESS);
}

vector<string> globalRet{};//TODO: move to fixture

int innerConvFunc(int num_msg, const struct pam_message **msg,
	     struct pam_response **resp, void *appdata_ptr)//TODO: move to fixture
{
  globalRet.push_back(string{msg[0]->msg});
  char *deletedByPam = new char[100];
  strcpy(deletedByPam,  "notneeded");
  pam_response rr{};

  rr.resp = deletedByPam;
  *resp = &rr;

  return PAM_SUCCESS;
}

class Unit : public ::testing::Test {
protected:
  pam_handle_t *pamh;
  struct pam_conv pam_conversation;
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_decrypt_flags_t flags = static_cast<gpgme_decrypt_flags_t>(0);
  gpgme_data_t in = NULL;
  gpgme_data_t out = NULL;
  
public:
  Unit()
  {
    pam_start("last-resort", "sharon", &pam_conversation, &pamh);

    gpgme_check_version (NULL);
    gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);

    gpgme_new(&ctx);
    gpgme_ctx_set_engine_info(ctx,
			      GPGME_PROTOCOL_OpenPGP,
			      NULL,
			      "/home/sharon/.gnupg");
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);

    pam_conversation.conv = &innerConvFunc;
    pam_conversation.appdata_ptr = nullptr;
    pam_set_item(pamh, PAM_CONV, static_cast<const void*>(&pam_conversation));
    globalRet.clear();
    fs::remove("/tmp/sig"s);
  }
  ~Unit()
  {
    pam_end(pamh, PAM_SUCCESS);
    if (out)
      gpgme_data_release (out);
    if (in)
      gpgme_data_release (in);
    gpgme_release (ctx);
  }
};

TEST_F(Unit, unitFixureTest)
{
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit, verifyUnusedFunctions)
{
  ASSERT_EQ(pam_setcred(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_acct_mgmt(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_open_session(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_close_session(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_chauthtok(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit, testNoSigFile)
{
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit, testBadSigFile)
{
  ofstream ovwrtSig("/tmp/sig"s);
  ovwrtSig << "badBad sigSig\n" << flush;
  ovwrtSig.close();
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

string getSig(string msg, string sender)
{
  gpgme_ctx_raii ctx{"~/.gnupg/"s};
  gpgme_op_keylist_start (ctx.get(), sender.c_str(), 0);
  keyRaii key;
  gpgme_op_keylist_next (ctx.get(), &key.get());
  gpgme_op_keylist_end(ctx.get());
  gpgme_signers_add (ctx.get(), key.get());
  gpgme_data_raii plain{msg};
  gpgme_data_raii sig{};
  gpgme_op_sign (ctx.get(), plain.get(), sig.get(), GPGME_SIG_MODE_NORMAL);
  constexpr int buffsize{500};
  char buf[buffsize + 1] = "";
  int ret = gpgme_data_seek (sig.get(), 0, SEEK_SET);
  string s{};
  while ((ret = gpgme_data_read (sig.get(), buf, buffsize)) > 0)
    {
      buf[ret] = '\0';
      s += string{buf};
    }
  cout << "DBG: "<< msg << endl << s << endl;
  return s;
}

TEST_F(Unit, testWrongSigFileWrongMachineId)
{
  ifstream curr{"/tmp/current"s};
  ASSERT_TRUE(curr.is_open());
  ASSERT_TRUE(curr.good());
  string readCurr{};
  getline(curr, readCurr);
  string nonce{readCurr.substr(readCurr.find(' ')+1)};
  string phonymsg{"badMachine "s + nonce};

  string sig{getSig(phonymsg, "vendor@mmodt.com"s)};
  ofstream putSig{"/tmp/sig"};
  putSig << sig << flush;
  putSig.close();
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit, testWrongSigFileWrongNonce)
{
  ifstream curr{"/tmp/current"s};
  ASSERT_TRUE(curr.is_open());
  ASSERT_TRUE(curr.good());
  string readCurr{};
  getline(curr, readCurr);
  string machindeId{readCurr.substr(0, readCurr.find(' '))};
  string phonymsg{machindeId + " badNonce"s};
  
  string sig{getSig(phonymsg, "vendor@mmodt.com"s)};
  ofstream putSig{"/tmp/sig"};
  putSig << sig << flush;
  putSig.close();
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit, testGoodSigFileWrongFprt)
{
  ifstream curr{"/tmp/current"s};
  ASSERT_TRUE(curr.is_open());
  ASSERT_TRUE(curr.good());
  string readCurr{};
  getline(curr, readCurr);
  string sig{getSig(readCurr, "appliance@mmodt.com"s)};
  ofstream putSig{"/tmp/sig"};
  putSig << sig << flush;
  putSig.close();
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit, testGoodSigFile)
{
  ifstream curr{"/tmp/current"s};
  ASSERT_TRUE(curr.is_open());
  ASSERT_TRUE(curr.good());
  string readCurr{};
  getline(curr, readCurr);
  string sig{getSig(readCurr, "vendor@mmodt.com"s)};
  ofstream putSig{"/tmp/sig"};
  putSig << sig << flush;
  putSig.close();
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_SUCCESS);
}

TEST_F(Unit, testCurrentMatchesConv)
{
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
  ifstream curr{"/tmp/current"s};
  ASSERT_TRUE(curr.is_open());
  ASSERT_TRUE(curr.good());
  string readCurr{};
  getline(curr, readCurr);
  ASSERT_NE(globalRet[0].find(readCurr),string::npos);
}

TEST_F(Unit, testNextRotates)
{
  pam_authenticate(pamh, 0);
}

TEST_F(Unit, testCurrRotates)
{
  pam_authenticate(pamh, 0);
}

TEST_F(Unit, testConvRotates)
{
  pam_authenticate(pamh, 0);
}

TEST_F(Unit, testRotationStress)
{
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

int main(int argc, char **argv) {
  ofstream initCurr("/tmp/current"s);
  initCurr << "devmachine1 initialRatchet" << flush;
  initCurr.close();
  
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}