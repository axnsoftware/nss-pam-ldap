/* ssh_keyring
 */

void ssh_keyring_init(void);


static void nslcd_ssh_key_add(fp,session,uid);
static void nslcd_ssh_key_all(fp,session,uid);
static void nslcd_ssh_key_allpub(fp,session,uid);
static void nslcd_ssh_key_bynamepub(fp,session,uid);
static void nslcd_ssh_key_rm(fp,session,uid);



static void write_keyring(TFILE *fp,MYLDAP_ENTRY *entry,uid_t *uid)
{
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
}

static void write_keypair(fp, char* identity, char *type, char* priv, char* pub)
{
  WRITE_LINE(fp, identity, ';', type, ';', pub, ';', priv);
}

static void write_keyring_pub(TFILE *fp,MYLDAP_ENTRY *entry,uid_t *uid)
{
  WRITE_INT32(fp,NSLCD_RESULT_BEGIN);
}

static void write_public_key(fp, char* identity, char *type, char* pub)
{
  WRITE_LINE(fp, identity, ';', type, ';', pub);
}


/* nslcd_ssh_keyring_all */
NSLCD_HANDLE_UID(
  ssh_keyring,all,
  uid_t uid;
  char filter[1024];
  /* FIXME:axn length check, allocation size, provable breach */
  char password[64];,
  READ_TYPE(fp,uid,uid_t);
  READ_STRING(fp,password);
  log_setrequest("ssh_keyring(all)=%d by uid=%d",(int)uid,(int)calleruid),
  NSLCD_ACTION_SSH_KEYRING_ALL,
  mkfilter_keyring_byuid(uid,filter,sizeof(filter),password,sizeof(password));,
  write_keyring(fp,entry,&uid);
  /* FIXME:axn must get rid of password */;
)

/* nslcd_ssh_keyring_allpub */
NSLCD_HANDLE_UID(
  ssh_keyring,allpub,
  uid_t uid;
  char filter[1024];
  READ_TYPE(fp,uid,uid_t);
  log_setrequest("ssh_keyring(allpub)=%d by uid=%d",(int)uid,(int)calleruid);,
  NSLCD_ACTION_SSH_KEYRING_ALLPUB,
  mkfilter_keyring_pubbyuid(uid,filter,sizeof(filter));,
  write_keyring_pub(fp,entry,&uid);
)
