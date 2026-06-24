export const CASUAL_REQUEST_ENDING = String.raw`(?:줘[요용욤여잉ㅇ~!?.ㅠㅜ]*|줭|죵|주라|줄래|라|세요|주세요|조)`;
export const AMOUNT_PATTERN = String.raw`(?:[0-9]+\s*만(?:원)?|[일이삼사오육칠팔구십백천]+\s*만(?:원)?|백\s*만(?:원)?|오십\s*만(?:원)?)`;

export const MONEY_REQUEST_ACTION = String.raw`(?:보내\s*${CASUAL_REQUEST_ENDING}|보내\s*줄\s*수|부쳐\s*${CASUAL_REQUEST_ENDING}|쏴\s*${CASUAL_REQUEST_ENDING}|쏴\s*줄\s*수|넣어\s*${CASUAL_REQUEST_ENDING}|빌려\s*(?:${CASUAL_REQUEST_ENDING}|주면|줄\s*수)|빌릴\s*(?:게|께)|내\s*${CASUAL_REQUEST_ENDING}|내\s*줄\s*수[있잇]?|내\s*주실|대신\s*(?:내|해)\s*(?:${CASUAL_REQUEST_ENDING}|줄래|줄\s*수)|해\s*줄\s*수[있잇]?|해\s*줄래|결제\s*${CASUAL_REQUEST_ENDING}|맡아\s*줘|해결\s*해\s*${CASUAL_REQUEST_ENDING}|땡겨\s*(?:${CASUAL_REQUEST_ENDING}|줄\s*수)|도와\s*${CASUAL_REQUEST_ENDING}|사\s*${CASUAL_REQUEST_ENDING}|입금|송금|(?<!자동)이체|필요|부탁|가능|먼저|ㄱㄱ)`;
export const MONEY_TRANSFER_ACTION = String.raw`(?:보내\s*${CASUAL_REQUEST_ENDING}|보내\s*줄\s*수|부쳐\s*${CASUAL_REQUEST_ENDING}|쏴\s*${CASUAL_REQUEST_ENDING}|쏴\s*줄\s*수|넣어\s*${CASUAL_REQUEST_ENDING}|빌려\s*(?:${CASUAL_REQUEST_ENDING}|주면|줄\s*수)|빌릴\s*(?:게|께)|내\s*${CASUAL_REQUEST_ENDING}|내\s*줄\s*수[있잇]?|내\s*주실|대신\s*(?:내|해)\s*(?:${CASUAL_REQUEST_ENDING}|줄래|줄\s*수)|해\s*줄\s*수[있잇]?|해\s*줄래|결제\s*${CASUAL_REQUEST_ENDING}|맡아\s*줘|해결\s*해\s*${CASUAL_REQUEST_ENDING}|땡겨\s*(?:${CASUAL_REQUEST_ENDING}|줄\s*수)|도와\s*${CASUAL_REQUEST_ENDING}|사\s*${CASUAL_REQUEST_ENDING}|입금|송금|(?<!자동)이체|먼저|ㄱㄱ)`;

export const FAMILY_MONEY_PURPOSE = String.raw`(?:돈|급전|용돈|소액|약값|약국|택시비|택시|숙박비|숙소비|밥값|회비|교통비|교통\s*카드|교통카드|지하철비|주차비|진료비|비용|수리비|수리\s*대금|수리대금|병원비|입원비|응급처치비|접수비|접수금|생활비|합의금|처리금|보증금|카드값|등록금|학원비|관리비|보험료|공과금|결제|알뜰\s*교통|알뜰교통|충전|상품권|기프트\s*카드|핀번호|PIN|${AMOUNT_PATTERN})`;
export const FAMILY_DEVICE_OR_PAYMENT_BLOCKER = String.raw`(?:폰|본폰|휴대폰|핸드폰|액정|카톡|카뱅|토스|인뱅|은행\s*앱|은행\s*로그인|계좌\s*앱|계좌|계좌\s*비활성|모바일\s*뱅킹|네이버페이|페이\s*앱|페이앱|페이|카드\s*앱|카드앱|통신\s*정지|통신정지|통신|전화|데이터|기기|인증서|유심|터치|배터리|충전|전원|알뜰\s*교통|알뜰교통)`;
export const FAMILY_BLOCKED_STATE = String.raw`(?:먹통|맛갔|침수|박살|물먹|벽돌|사망|사망함|죽어|죽어서|안\s*돼|안돼|못\s*써|못\s*해|못함|막힘|막혀|잠겨|잠김|비활성|비활성됨|정지\s*걸려|걸려|안\s*터져|터지지\s*않|초기화|초기화돼|없거든|점검\s*걸려|튕겨|오류|오류남|나가|안\s*켜|꺼졌|터치\s*안\s*먹어|터치\s*안\s*먹)`;

export const ACCOUNT_REQUEST_TARGET = String.raw`(?:계좌\s*번호|계좌\s*정보|계좌정보|계좌|은행명)`;
export const TRUSTED_ACCOUNT_PURPOSE = String.raw`(?:용돈|회비|정산|점심값|밥값|월세|집주인|등록금|학교\s*포털|포털|병원비)`;
export const TRUSTED_ACCOUNT_RELATIONSHIPS = ['family', 'friend', 'coworker'] as const;

export const CREDENTIAL_REQUEST_TARGET = String.raw`(?:인증\s*번호|인\s*증\s*번\s*호|인증\s*코드|인증코드|인증\s*문자|인증문자|OTP|오\s*티\s*피|ㅇ\s*ㅈ\s*ㅂ\s*ㅎ|승인\s*번호|승인\s*코드|승인코드|확인\s*번호|확인번호|확인\s*코드|확인코드|열람\s*코드|열람코드|보안\s*문자|보안문자|보안\s*코드|보안코드|보안\s*숫자|보안숫자|일회용\s*번호|일회용번호|ARS\s*인증|ARS|비밀\s*번호|비밀번호|비번|암호|공동\s*인증서|공동인증서|공인\s*인증서|공인인증서|인증서|보안\s*카드|카드\s*비번|잠금\s*번호|화면\s*잠금\s*번호|cvc|cvv)`;
export const CREDENTIAL_DISCLOSURE_ACTION = String.raw`(?:불러|알려|말해|말씀|입력|전송|제출|공유|보내|읽어|읽어주|답장|회신|확인|누르|승인)`;
export const APP_PERMISSION_TERMS = String.raw`(?:알림\s*접근|알림접근|접근성\s*권한|접근성\s*허용|문자\s*읽기|문자읽기|권한\s*허용|권한|화면\s*잠금|화면잠금|화면\s*공유|화면공유|원격\s*지원|원격지원|원격\s*제어|원격제어)`;
