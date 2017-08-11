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
		port = os.Getenv("HTTP_PLATFORM_PORT")
		if port == "" {
			log.Fatal("$PORT must be set")
		}
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
		request.Host = strings.TrimSpace(request.Host)

		if len(request.Host) <= 0 {
			c.JSON(400, gin.H{"Error": "Invalid request"})
			return
		}

		internalHost := request.Host
		if !govalidator.IsDialString(request.Host) {
			if !govalidator.IsHost(request.Host) {
				c.JSON(400, gin.H{"Host": request.Host, "Error": "Invalid hostname"})
				return
			}
			internalHost += ":22"
		}

		log.Printf("Getting Keys for '%s'\n", internalHost)

		keys, err := sshkeys.GetKeys(internalHost, timeout)
		if err != nil {
			log.Printf("'%s' Failed: %s\n", internalHost, err.Error())
			c.JSON(500, gin.H{"Host": request.Host, "Error": err.Error()})
			return
		}

		log.Printf("Got %d Keys for '%s'\n", len(keys), internalHost)

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
