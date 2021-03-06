#include "common-raii/common-raii.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#include <curl/curl.h>
#include <gpgme.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <sys/types.h>
}

using namespace std;
namespace fs = std::filesystem;
using namespace commonRaii;

string sigFile{"/lastresort.sig"s};
string currFile{"/.lastresort_rollingstate"s};
string testMountPoint{"/technician"};
string fngrprnt{}, mntPrefix{}, mountPoint{};

TEST(unitTests, emptyTest) {
  pam_handle_t *pamh;
  struct pam_conv pam_conversation;
  string module_name{"last-resort"s};
  auto pw{getpwuid(geteuid())};
  string user_name{pw->pw_name};
  ASSERT_EQ(pam_start(module_name.c_str(), user_name.c_str(), &pam_conversation,
                      &pamh),
            PAM_SUCCESS);
  ASSERT_EQ(pam_authenticate(pamh, PAM_SILENT), PAM_PERM_DENIED);
  ASSERT_EQ(pam_end(pamh, PAM_SUCCESS), PAM_SUCCESS);
}

vector<string> globalRet{}; // TODO: move to fixture

int innerConvFunc(int num_msg, const struct pam_message **msg,
                  struct pam_response **resp,
                  void *appdata_ptr) // TODO: move to fixture
{
  globalRet.push_back(string{msg[0]->msg});
  char *deletedByPam = new char[100];
  strcpy(deletedByPam, "notneeded");
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
  Unit() {
    auto pw{getpwuid(geteuid())};
    pam_start("last-resort", pw->pw_name, &pam_conversation, &pamh);

    gpgme_check_version(NULL);
    gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);

    gpgme_new(&ctx);
    gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP, NULL, "~/.gnupg");
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);

    pam_conversation.conv = &innerConvFunc;
    pam_conversation.appdata_ptr = nullptr;
    pam_set_item(pamh, PAM_CONV, static_cast<const void *>(&pam_conversation));
    globalRet.clear();
    fs::remove(sigFile);
  }
  ~Unit() {
    pam_end(pamh, PAM_SUCCESS);
    if (out)
      gpgme_data_release(out);
    if (in)
      gpgme_data_release(in);
    gpgme_release(ctx);
  }
};

TEST_F(Unit, unitFixureTest) {
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit, verifyUnusedFunctions) {
  ASSERT_EQ(pam_setcred(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_acct_mgmt(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_open_session(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_close_session(pamh, 0), PAM_PERM_DENIED);
  ASSERT_EQ(pam_chauthtok(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit, testNoSigFile) {
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit, testBadSigFile) {
  ofstream ovwrtSig(sigFile);
  ovwrtSig << "badBad sigSig\n" << flush;
  ovwrtSig.close();
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

string getSig(string msg, string sender) {
  gpgme_ctx_raii ctx{"~/.gnupg/"s};
  gpgme_op_keylist_start(ctx.get(), sender.c_str(), 0);
  keyRaii key;
  gpgme_op_keylist_next(ctx.get(), &key.get());
  gpgme_op_keylist_end(ctx.get());
  gpgme_signers_add(ctx.get(), key.get());
  gpgme_data_raii plain{msg};
  gpgme_data_raii sig{};
  gpgme_op_sign(ctx.get(), plain.get(), sig.get(), GPGME_SIG_MODE_NORMAL);
  constexpr int buffsize{500}; // TODO: refactor to func
  char buf[buffsize + 1] = "";
  int ret = gpgme_data_seek(sig.get(), 0, SEEK_SET);
  string s{};
  while ((ret = gpgme_data_read(sig.get(), buf, buffsize)) > 0) {
    buf[ret] = '\0';
    s += string{buf};
  }
  return s;
}

TEST_F(Unit, testWrongSigFileWrongMachineId) {
  ifstream curr{currFile};
  ASSERT_TRUE(curr.is_open());
  ASSERT_TRUE(curr.good());
  string readCurr{};
  getline(curr, readCurr);
  string nonce{readCurr.substr(readCurr.find(' ') + 1)};
  string phonymsg{"badMachine "s + nonce};

  string sig{getSig(phonymsg, fngrprnt)};
  ofstream putSig{sigFile};
  putSig << sig << flush;
  putSig.close();
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit, testWrongSigFileWrongNonce) {
  ifstream curr{currFile};
  ASSERT_TRUE(curr.is_open());
  ASSERT_TRUE(curr.good());
  string readCurr{};
  getline(curr, readCurr);
  string machindeId{readCurr.substr(0, readCurr.find(' '))};
  string phonymsg{machindeId + " badNonce"s};

  string sig{getSig(phonymsg, fngrprnt)};
  ofstream putSig{sigFile};
  putSig << sig << flush;
  putSig.close();
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

TEST_F(Unit, testGoodSigFileWrongFprt) {
  ifstream curr{currFile};
  ASSERT_TRUE(curr.is_open());
  ASSERT_TRUE(curr.good());
  string readCurr{};
  getline(curr, readCurr);
  string sig{getSig(readCurr, "appliance@mmodt.com"s)};
  ofstream putSig{sigFile};
  putSig << sig << flush;
  putSig.close();
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
}

string simulateUser(string currSrc) {
  ifstream curr{currSrc};
  string readCurr{};
  getline(curr, readCurr);
  string sig{getSig(readCurr, fngrprnt)};
  ofstream putSig{sigFile};
  putSig << sig << flush;
  putSig.close();
  return readCurr;
}

TEST_F(Unit, testGoodSigFile) {
  for (int i{0}; i < 10; i++) {
    simulateUser(currFile);
    ASSERT_EQ(pam_authenticate(pamh, 0), PAM_SUCCESS);
  }
}

TEST_F(Unit, testSigFileOvrwrt) {
  simulateUser(currFile);
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_SUCCESS);
  for (int i{0}; i < 10; i++) {
    simulateUser(sigFile);
    ASSERT_EQ(pam_authenticate(pamh, 0), PAM_SUCCESS);
  }
}

TEST_F(Unit, testCurrentMatchesConv) {
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_PERM_DENIED);
  ifstream curr{currFile};
  ASSERT_TRUE(curr.is_open());
  ASSERT_TRUE(curr.good());
  string readCurr{};
  getline(curr, readCurr);
  ASSERT_EQ(globalRet.size(), 1);
  ASSERT_NE(globalRet[0].find(readCurr), string::npos);
}

TEST_F(Unit, testCurrRotatesOnSuccess) {
  auto s1{simulateUser(currFile)};
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_SUCCESS);
  auto s2{simulateUser(currFile)};
  ASSERT_EQ(pam_authenticate(pamh, 0), PAM_SUCCESS);
  ASSERT_EQ(s1.substr(0, s1.find(' ')), s2.substr(0, s2.find(' ')));
  ASSERT_NE(s1.substr(s1.find(' '), string::npos),
            s2.substr(s2.find(' '), string::npos));
}

TEST_F(Unit, testCurrRemainsOnFail) {
  pam_authenticate(pamh, 0);
  ifstream curr1{currFile};
  string readCurr1{};
  getline(curr1, readCurr1);

  pam_authenticate(pamh, 0);
  ifstream curr2{currFile};
  string readCurr2{};
  getline(curr2, readCurr2);

  ASSERT_EQ(readCurr1, readCurr2);
}

int autoConvFunc(int num_msg, const struct pam_message **msg,
                 struct pam_response **resp,
                 void *appdata_ptr) // TODO: move to fixture
{                                   // TODO: remove duplication with Unit
  stringstream msgStream{string{msg[0]->msg}};
  char *deletedByPam = new char[100];
  strcpy(deletedByPam, "notneeded");
  pam_response rr{};
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_decrypt_flags_t flags = static_cast<gpgme_decrypt_flags_t>(0);
  gpgme_data_t in = NULL;
  gpgme_data_t out = NULL;

  rr.resp = deletedByPam;
  *resp = &rr;

  gpgme_check_version(NULL);
  gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);

  gpgme_new(&ctx);
  gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP, NULL, "~/.gnupg");
  gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);

  string line{};
  getline(msgStream, line);
  string sigFileFromMsg{line.substr(line.find_last_of(" ") + 1)};
  getline(msgStream, line);
  getline(msgStream, line);
  string readCurr{line};
  string sigFile{mountPoint + sigFileFromMsg};
  string sig{getSig(readCurr, fngrprnt)};
  ofstream putSig{sigFile};
  putSig << sig << flush;
  putSig.close();

  if (out)
    gpgme_data_release(out);
  if (in)
    gpgme_data_release(in);
  gpgme_release(ctx);
  globalRet.push_back(readCurr);

  return PAM_SUCCESS;
}

TEST(unittests, fullFlowInConv) // TODO: remove duplication with Unit
{
  pam_handle_t *pamh;
  struct pam_conv pam_conversation;
  auto pw{getpwuid(geteuid())};
  pam_start("last-resort", pw->pw_name, &pam_conversation, &pamh);
  pam_conversation.conv = &autoConvFunc;
  pam_conversation.appdata_ptr = nullptr;
  pam_set_item(pamh, PAM_CONV, static_cast<const void *>(&pam_conversation));
  globalRet.clear();
  int t{10};
  for (int i{0}; i < t; i++)
    ASSERT_EQ(pam_authenticate(pamh, 0), PAM_SUCCESS);
  sort(globalRet.begin(), globalRet.end());
  vector<string> uniq{globalRet.begin(),
                      unique(globalRet.begin(), globalRet.end())};
  ASSERT_EQ(t, uniq.size());
  pam_end(pamh, PAM_SUCCESS);
}

int main(int argc, char **argv) {
  auto pw{getpwuid(geteuid())};
  string homePrefix{pw->pw_dir};
  ifstream conf{homePrefix + "/.lastresort_conf"s};
  conf >> fngrprnt;
  conf >> mntPrefix;

  sigFile = mntPrefix + testMountPoint + sigFile;
  mountPoint = mntPrefix + testMountPoint + "/"s;
  currFile = homePrefix + currFile;
  cout << fngrprnt << endl;
  cout << mntPrefix << endl;
  cout << sigFile << endl;
  cout << mountPoint << endl;
  cout << currFile << endl;
  {
    ofstream initCurr(currFile);
    initCurr << "devmachine1 initialRatchet"s << endl;
  }
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
