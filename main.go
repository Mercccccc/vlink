package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
	"github.com/develop1024/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"gopkg.in/yaml.v2"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

type Config struct {
	Mysql Mysql
	Jwt Jwt
	Sms Sms
	Oss Oss
}

type Oss struct {
	AccessKeyid string
	AccessKeysecret string
	Rolearn string
}

type Sms struct {
	Password string `yaml:"password"`
	Loginname string `yaml:"loginname"`
	Spcode string `yaml:"spcode"`
}

type Mysql struct {
	Username string `yaml:"username"`
	Port string `yaml:"port"`
	Host string `yaml:"host"`
	Password string `yaml:"password"`
}

type Jwt struct {
	Mysecret string `yaml:"mysecret"`
}

type MyClaims struct {
	UserID string `json:"userID"`
	jwt.StandardClaims
}

type Notification struct {
	ID string `gorm:"primarykey"`
	Content string `json:"content"`
	Phone string `json:"phone"`
	Type string `json:"type"`
	UserID uint
}

type Families struct {
	ID uint `json:"id" gorm:"primarykey"`
	BindID string `json:"bindphone"`
	UserID uint
}

type User struct {
	ID uint `json:"id" form:"id" gorm:"primarykey"`
	Username string `json:"username" form:"username"`
	Phone string `json:"phone" form:"phone"`
	Code int `json:"code" form:"code"`
	Profile string `json:"profile"`
	CodeCreateAt time.Time
}

var con Config
const TokenExpireDuration = time.Hour * 2
var MySecret = []byte(con.Jwt.Mysecret)

func main()  {
	Initial()

	dsn := "root:1351698043whl@tcp(127.0.0.1:3306)/vlink?charset=utf8mb4&parseTime=True&loc=Local"
	db, _ := gorm.Open(mysql.Open(dsn), &gorm.Config{})

	fmt.Println(dsn)
	e := db.AutoMigrate(&User{})
	if e != nil {
		fmt.Printf("%v", e)
	}

	e = db.AutoMigrate(&Families{})
	if e != nil {
		fmt.Printf("%v", e)
	}

	e = db.AutoMigrate(&Notification{})
	if e != nil {
		fmt.Printf("%v", e)
	}

	r := gin.Default()
	r.Use(Cors())
	authGroup := r.Group("/auth", UserJudge())

	r.POST("/phone/code", func(c *gin.Context) {
		var register User
		var exist User

		if err := c.ShouldBind(&register); err == nil {
			if VerifyMobileFormat(register.Phone) {
				register.CodeCreateAt = time.Now()
				result := db.Table("users").Where("Phone = ?", register.Phone).Take(&exist)

				if result.RowsAffected == 0 {
					register.Code = Send(register.Phone)
					db.Model(&User{}).Create(&register)
					c.JSON(200, gin.H{
						"code": 0,
						"message": "发送成功",
					})
				} else if sub := time.Now().Sub(exist.CodeCreateAt); sub.Minutes() > 1 {
					register.Code = Send(register.Phone)
					db.Table("users").Where("phone = ?", register.Phone).Update("code_create_at", time.Now())
					db.Table("users").Where("phone = ?", register.Phone).Update("code", &register.Code)
					c.JSON(200, gin.H{
						"code": 0,
						"message": "发送成功",
					})
				} else {
					c.JSON(200, gin.H{
						"code": 1,
						"message": "请求过快",
					})
				}
			} else {
				c.JSON(200, gin.H{
					"code": 2,
					"message": "手机号有误",
				})
			}
		}
	})

	r.POST("/login", func(c *gin.Context) {
		var register User
		var exist User

		if err := c.ShouldBind(&register); err == nil {
			result := db.Table("users").Where("Phone = ?", register.Phone).Take(&exist)
			if result.RowsAffected == 0 {
				c.JSON(200, gin.H{
					"code": 1,
					"message": "未发送验证码",
				})
			} else if exist.Code == register.Code {
				if time.Now().Sub(exist.CodeCreateAt).Minutes() >= 10{
					c.JSON(200, gin.H{
						"code": 3,
						"message": "验证码有效期超时",
					})
				} else {
					token, _ := GenToken(strconv.Itoa(int(exist.ID)))
					if exist.Username == "" {
						c.JSON(200, gin.H{
							"code": 0,
							"message": "注册成功",
							"data": gin.H{
								"id": exist.ID,
								"token": token,
								"login": 0,
								"profile": "",
							},
						})
					} else {
						c.JSON(200, gin.H{
							"code": 0,
							"message": "登陆成功",
							"data": gin.H{
								"id": exist.ID,
								"token": token,
								"login": 1,
								"profile": exist.Profile,
							},
						})
					}
				}
			} else {
				c.JSON(200, gin.H{
					"code": 2,
					"message": "验证码错误",
				})
			}
		}
	})

	authGroup.POST("/user/name", func(c *gin.Context) {
		var user User

		if e := c.ShouldBind(&user); e == nil {
			claim, _ := ParseToken(c.GetHeader("token"))
			user.ID = ToUint(claim.UserID)

			db.Table("users").Where("id = ?", user.ID).Update("username", user.Username)

			c.JSON(200, gin.H{
				"code": 0,
				"message": "设置成功",
			})
		}
	})

	authGroup.GET("/sts/gettoken", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"code": 0,
			"message": "请求成功",
			"data": OssToken(),
		})
	})

	authGroup.GET("/user/profile", func(c *gin.Context) {
		var user User

		claim, _ := ParseToken(c.GetHeader("token"))
		id := ToUint(claim.UserID)

		db.Table("users").Where("id = ?", id).Take(&user)

		url := "https://ncuvlink.oss-cn-beijing.aliyuncs.com" + user.Profile

		c.JSON(200, gin.H{
			"code": 0,
			"message": "请求成功",
			"url": url,
		})
	})

	authGroup.POST("/user/profile", func(c *gin.Context) {
		var user User

		if e := c.ShouldBind(&user); e == nil {
			claim, _ := ParseToken(c.GetHeader("token"))
			user.ID = ToUint(claim.UserID)

			db.Table("users").Where("id = ?", user.ID).Update("profile", user.Profile)

			c.JSON(200, gin.H{
				"code": 0,
				"message": "设置成功",
			})
		}
	})

	authGroup.POST("/user/bind", func(c *gin.Context) {
		var user User

		if err := c.ShouldBind(&user); err == nil {


			//db.Table("notifications").Create()
		}
	})

	r.Run(":8080")
}

func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
		c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
		c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Cache-Control, Content-Language, Content-Type")
		c.Header("Access-Control-Allow-Credentials", "true")

		if method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
		}

		c.Next()
	}
}

func GenToken(userid string) (string, error) {
	// 创建一个我们自己的声明
	c := MyClaims{
		userid, // 自定义字段
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(TokenExpireDuration).Unix(), // 过期时间
			Issuer:    "vlink",                               // 签发人
		},
	}
	// 使用指定的签名方法创建签名对象
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	// 使用指定的secret签名并获得完整的编码后的字符串token
	return token.SignedString(MySecret)
}

// ParseToken 解析JWT
func ParseToken(tokenString string) (*MyClaims, error) {
	// 解析token
	token, err := jwt.ParseWithClaims(tokenString, &MyClaims{}, func(token *jwt.Token) (i interface{}, err error) {
		return MySecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*MyClaims); ok && token.Valid { // 校验token
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

func OssToken() *sts.AssumeRoleResponse {
	//构建一个阿里云客户端, 用于发起请求。
	//构建阿里云客户端时，需要设置AccessKey ID和AccessKey Secret。
	client, err := sts.NewClientWithAccessKey("cn-hangzhou", con.Oss.AccessKeyid, con.Oss.AccessKeysecret)

	//构建请求对象。
	request := sts.CreateAssumeRoleRequest()
	request.Scheme = "https"

	//设置参数。关于参数含义和设置方法，请参见《API参考》。
	request.RoleArn = con.Oss.Rolearn
	request.RoleSessionName = "vlink"

	//发起请求，并得到响应。
	response, err := client.AssumeRole(request)
	if err != nil {
		fmt.Print(err.Error())
	}

	return response
}

func Initial() {
	yamlFile, err := ioutil.ReadFile("./config/config.yaml")
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, con)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
}

func Send(phone string) int {
	code := rand.Intn(999999)
	var msg string
	msg = fmt.Sprintf("你的验证码为%d.", code)
	var e error
	gbkmsg, e := ioutil.ReadAll(transform.NewReader(bytes.NewReader([]byte(msg)), simplifiedchinese.GBK.NewEncoder()))
	if e != nil {
		fmt.Printf("%v\n", e)
	}
	url := fmt.Sprintf("http://smsapi.ums86.com:8888/sms/Api/Send.do?SpCode=%s&LoginName=%s&Password=%s&MessageContent=%s&UserNumber=%s&SerialNumber=%v",
		con.Sms.Spcode, con.Sms.Loginname, con.Sms.Password, gbkmsg, phone, time.Now().UnixNano())
	res, err := http.Post(url, "application/x-www-form-urlencoded", nil)
	if err != nil{
		fmt.Printf("%v", err)
	}

	defer res.Body.Close()

	return code
}

func VerifyMobileFormat(mobileNum string) bool {
	regular := "^((13[0-9])|(14[5,7])|(15[0-3,5-9])|(17[0,3,5-8])|(18[0-9])|166|198|199|(147))\\d{8}$"

	reg := regexp.MustCompile(regular)
	return reg.MatchString(mobileNum)
}

func UserJudge() gin.HandlerFunc {
	return func(ctx *gin.Context) {
			token := ctx.Request.Header.Get("token")
			_, err := ParseToken(token)

			if err != nil {
				ctx.JSON(http.StatusUnauthorized, gin.H{
					"code": 7,
					"message": err,
				})
				ctx.Abort()
				return
			}

			ctx.Next()
	}
}

func ToUint(n string) uint {
	a, err := strconv.Atoi(n)
	if err != nil{
		fmt.Println(err)
	}
	return uint(a)
}