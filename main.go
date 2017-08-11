package main

import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Eun/sshkeys"
	"github.com/asaskevich/govalidator"

	"github.com/gin-gonic/gin"
	_ "github.com/heroku/x/hmetrics/onload"
)

const (
	authorized_keys = 1
	fingerprintMD5  = 2
	fingerprintSHA1 = 3
)

func sumToString(sum []byte) (s string) {
	for i := 0; i < len(sum); i++ {
		s += fmt.Sprintf("%02x", sum[i])
		if i < len(sum)-1 {
			s += ":"
		}
	}
	return s
}

func keyToString(key ssh.PublicKey, format int) string {
	switch format {
	case fingerprintMD5:
		sum := md5.Sum(key.Marshal())
		return fmt.Sprintf("%s", sumToString(sum[:]))
	case fingerprintSHA1:
		sum := sha1.Sum(key.Marshal())
		return fmt.Sprintf("%s", sumToString(sum[:]))
	case authorized_keys:
		fallthrough
	default:
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	}
}

func main() {

	port := os.Getenv("PORT")

	if port == "" {
		log.Fatal("$PORT must be set")
	}

	router := gin.New()
	router.Use(gin.Logger())
	router.Static("/", "static")

	timeout, _ := time.ParseDuration("30s")

	type CheckRequest struct {
		Host string
	}

	router.POST("/check", func(c *gin.Context) {
		var request CheckRequest
		err := c.BindJSON(&request)
		if err != nil {
			c.JSON(400, gin.H{"Error": "Invalid request"})
			return
		}
		if len(request.Host) <= 0 {
			c.JSON(400, gin.H{"Error": "Invalid request"})
			return
		}

		request.Host = strings.TrimSpace(request.Host)
		internalHost := request.Host
		if !govalidator.IsDialString(request.Host) {
			if !govalidator.IsHost(request.Host) {
				c.JSON(400, gin.H{"Error": "Invalid hostname"})
				return
			}
			internalHost += ":22"
		}

		keys, err := sshkeys.GetKeys(internalHost, timeout)
		if err != nil {
			c.JSON(500, gin.H{"Error": err})
			return
		}

		var printableKeys []gin.H

		for i := 0; i < len(keys); i++ {
			printableKeys = append(printableKeys, gin.H{
				"Key":  keyToString(keys[i], authorized_keys),
				"MD5":  keyToString(keys[i], fingerprintMD5),
				"SHA1": keyToString(keys[i], fingerprintSHA1),
			})
		}

		c.JSON(200, gin.H{"Host": request.Host, "PublicKeys": printableKeys})

	})

	router.Run(":" + port)
}
