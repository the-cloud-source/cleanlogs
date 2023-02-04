package cleanlogs

import (
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// github.com/grafana/grafana/pkg/api
// github.com/grafana/grafana/pkg/api/http_server.go
// github.com/grafana/grafana/pkg/web/router.go

var deny = []netip.Prefix{}
var allow = []netip.Prefix{}

const (
	env_allow  = "CLEAN_ALLOW_PREFIX"
	env_deny   = "CLEAN_DENY_PREFIX"
	env_append = "CLEAN_APPEND_PREFIX"
)

func init() {

	envDeny := os.Getenv(env_deny)
	envAllow := os.Getenv(env_allow)
	envAppend := os.Getenv(env_append)

	denyList := envDeny
	allowList := ""

	if envAllow == "" && envDeny == "" {
		allowList = "127.0.0.1/8" + " "
		a, _ := net.InterfaceAddrs()
		for _, v := range a {
			allowList += v.String() + " "
		}
		allowList += envAppend
	}

	seen := map[string]bool{}
	for _, p := range strings.Split(allowList, " ") {
		p = strings.TrimSpace(p)
		if _, is := seen[p]; is {
			continue
		}
		prefix, err := netip.ParsePrefix(p)
		if err == nil {
			allow = append(allow, prefix)
		}
	}

	seen = map[string]bool{}
	for _, p := range strings.Split(denyList, " ") {
		p = strings.TrimSpace(p)
		if _, is := seen[p]; is {
			continue
		}
		prefix, err := netip.ParsePrefix(p)
		if err == nil {
			deny = append(deny, prefix)
		}
	}
}

func CleanLogs() gin.HandlerFunc {

	if len(allow) > 0 {
		return func(c *gin.Context) {
			reqRemoteAddr, _, _ := net.SplitHostPort(c.Request.RemoteAddr)
			reqRemoteIP, err := netip.ParseAddr(reqRemoteAddr)
			if err != nil {
				c.Next()
				return
			}

			for _, p := range allow {
				if p.Contains(reqRemoteIP) {
					c.Next()
					return
				}
			}
			c.AbortWithStatus(http.StatusNotFound)
		}
	}

	if len(deny) > 0 {
		return func(c *gin.Context) {
			reqRemoteAddr, _, _ := net.SplitHostPort(c.Request.RemoteAddr)
			reqRemoteIP, err := netip.ParseAddr(reqRemoteAddr)
			if err != nil {
				c.Next()
				return
			}

			for _, p := range deny {
				if p.Contains(reqRemoteIP) {
					c.AbortWithStatus(http.StatusNotFound)
					return
				}
			}
			c.Next()
		}
	}
	return func(c *gin.Context) { c.Next() }
}
