#define DQ(str) "\"" #str "\""
#define DQC(str) "\"" #str "\" : "
#define LBUF lbuf
#define ADDRESULT buf_add(LBUF, line, strlen(line));
#define AS(val)  buf_add(LBUF, val, strlen (val));
#define JS(key, val) snprintf(line, DEFAULT_LINE_LENGTH, "\"" #key"\" : \"%s\" , ",  val); ADDRESULT  
#define JS_NC(key, val) snprintf(line, DEFAULT_LINE_LENGTH,"\"" #key"\" : \"%s\" ",  val); ADDRESULT 
#define JSDOT(key, val) snprintf(line, DEFAULT_LINE_LENGTH, "\"" #key"\" : \"%s.\" , ",  val); ADDRESULT
#define JS1(key, fmt, val) snprintf(line, DEFAULT_LINE_LENGTH, "\"" #key"\" : "#fmt" , ",  val); ADDRESULT
#define JD(key, val) snprintf(line, DEFAULT_LINE_LENGTH, "\"" #key"\" : %d , ",  val); ADDRESULT
#define JD_NC(key, val) snprintf(line, DEFAULT_LINE_LENGTH, "\"" #key"\" : %d ",  val); ADDRESULT
#define JU(key, val) snprintf(line, DEFAULT_LINE_LENGTH, "\"" #key"\" : %u , ",  val); ADDRESULT
#define JU_NC(key, val) snprintf(line, DEFAULT_LINE_LENGTH, "\"" #key"\" : %u",  val); ADDRESULT
#define JC snprintf(line, DEFAULT_LINE_LENGTH, ","); ADDRESULT
