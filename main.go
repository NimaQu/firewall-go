package main

import (
	"github.com/coreos/go-iptables/iptables"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"strconv"
	"strings"
)

var Env map[string]string

func worker(c *gin.Context) {
	chain := c.GetString("chain")
	//table := c.GetString("table")
	table := "filter"
	action := c.GetString("action")
	port, _ := c.Get("port")
	portStr := strconv.Itoa(int(port.(int64)))
	userIp := c.ClientIP()
	ipt, err := iptables.New()
	exist, _ := ipt.Exists(table, chain, "-p", "tcp", "--dport", portStr, "-s", userIp, "-j", action)
	if !exist {
		err = ipt.Insert(table, chain, 1, "-p", "tcp", "--dport", portStr, "-s", userIp, "-j", action)
	}
	exist, _ = ipt.Exists(table, chain, "-p", "udp", "--dport", portStr, "-s", userIp, "-j", action)
	if !exist {
		err = ipt.Insert(table, chain, 1, "-p", "udp", "--dport", portStr, "-s", userIp, "-j", action)
	}
	if err != nil {
		c.AbortWithStatusJSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "ok"})
}

func validator(c *gin.Context) {
	key, exist := c.GetQuery("auth")
	if !exist || key != Env["API_KEY"] {
		c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
		return
	}
	chain := strings.ToUpper(c.Param("chain"))
	//table := strings.ToUpper(c.Param("table"))
	action := strings.ToUpper(c.Param("action"))
	port, err := strconv.ParseInt(c.Param("port"), 10, 32)
	if err != nil {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid port"})
		return
	}

	if chain != "INPUT" && chain != "OUTPUT" && chain != "FORWARD" {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid chain"})
		return
	}
	//if table != "FILTER" && table != "NAT" && table != "MANGLE" {
	//	c.AbortWithStatusJSON(400, gin.H{"error": "invalid table"})
	//	return
	//}
	if action != "ACCEPT" && action != "DROP" && action != "REJECT" {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid action"})
		return
	}
	portMin, err := strconv.ParseInt(strings.Split(Env["PORT"], ":")[0], 10, 32)
	portMax, err := strconv.ParseInt(strings.Split(Env["PORT"], ":")[1], 10, 32)
	if err != nil {
		panic(err)
	}
	if port < portMin || port > portMax || port < 1 || port > 65535 {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid port"})
		return
	}
	c.Set("chain", chain)
	//c.Set("table", table)
	c.Set("action", action)
	c.Set("port", port)
	c.Next()
}

func main() {
	// load env file
	var err error
	Env, err = godotenv.Read()
	if err != nil {
		panic(err)
	}
	ipt, err := iptables.New()
	err = ipt.ClearAll()
	// reject all port listed in env
	err = ipt.Append("filter", "INPUT", "-p", "tcp", "--dport", Env["PORT"], "-j", "DROP")
	err = ipt.Append("filter", "INPUT", "-p", "udp", "--dport", Env["PORT"], "-j", "DROP")
	if err != nil {
		panic(err)
	}
	if Env["DEBUG"] == "true" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()
	router.GET(":chain/filter/:action/:port", validator, worker)
	_ = router.RunTLS(Env["HOST"], Env["CERT"], Env["KEY"])
}
