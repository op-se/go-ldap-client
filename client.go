package opldap

import (
	"crypto/tls"
	"fmt"
	"log"
	"regexp"
	"strings"

	"gopkg.in/ldap.v3"
)

type LDAPClient struct {
	Attributes         []string
	Base               string
	BindDN             string
	BindPassword       string
	GroupFilter        string // e.g. "(memberUid=%s)"
	Host               string
	ServerName         string
	UserFilter         string // e.g. "(uid=%s)"
	Conn               *ldap.Conn
	Port               int
	InsecureSkipVerify bool
	UseSSL             bool
	SkipTLS            bool
	ClientCertificates []tls.Certificate // Adding client certificates
}

func (lc *LDAPClient) Connect() error {

	if lc.Conn == nil {
		var l *ldap.Conn
		var err error
		l, err = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", lc.Host, lc.Port))

		if err != nil {
			log.Fatal(err)
		}
		// defer l.Close()

		err = l.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			log.Fatal(err)
		}
		lc.Conn = l
	}

	return nil

}

func (lc *LDAPClient) Close() {
	lc.Conn.Close()
}

func (lc *LDAPClient) GetAllGroups() {
	searchRequest := ldap.NewSearchRequest(
		lc.Base, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(ObjectClass=group)", // The filter to apply
		[]string{"dn", "cn", "ou", "memberOf", "member", "mail"}, // A list attributes to retrieve
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		log.Fatal("ERR", err)
	}
	groups := []string{}
	for _, entry := range sr.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
		fmt.Println(entry.DN)
	}
}

func (lc *LDAPClient) GetGroupsOfUser(username string) ([]string, error) {
	// func (lc *LDAPClient) GetGroupsOfUser(filter string) {

	searchRequest := ldap.NewSearchRequest(
		lc.Base, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.GroupFilter, username),            // The filter to apply
		[]string{"dn", "cn", "ou", "memberOf", "member"}, // A list attributes to retrieve
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		log.Fatal("ERR", err)
	}
	groups := []string{}
	for _, entry := range sr.Entries {
		grp := formatGroup(entry.DN)
		groups = append(groups, grp)
	}
	return groups, nil
}

// samaccountname
// abc

func (lc *LDAPClient) GetUserBySAM(username string) (string, string) {

	searchRequest := ldap.NewSearchRequest(
		lc.Base, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(samaccountname=%s)", username),                          // The filter to apply
		[]string{"dn", "cn", "ou", "memberOf", "member", "userPrincipalName"}, // A list attributes to retrieve
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		log.Fatal("ERR", err)
	}

	if len(sr.Entries) == 1 {
		return sr.Entries[0].DN, sr.Entries[0].GetAttributeValue("userPrincipalName")
	}
	return "", ""
}

func Reverse(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func formatGroup(s string) string {
	re := regexp.MustCompile(`(,DC.*)`)
	rDN := re.FindAllString(s, -1)[0]
	s = strings.ReplaceAll(s, rDN, "")
	s = strings.ReplaceAll(s, "CN=", "")
	s = strings.ReplaceAll(s, "OU=", "")
	ns := strings.Split(s, ",")

	Reverse(ns)

	grp := fmt.Sprintf("/%s", strings.Join(ns, "/"))

	return grp
}
