// cmd/vsphere-report — standalone vSphere inventory report tool.
//
// Usage:
//
//	go run ./cmd/vsphere-report [flags]
//
// Flags (each falls back to the matching env var):
//
//	--host       VSPHERE_HOST      vCenter host/IP (e.g. 172.16.7.10)
//	--user       VSPHERE_USER      username (default: administrator@vsphere.local)
//	--password   VSPHERE_PASSWORD  password
//	--dc         VSPHERE_DC        datacenter name (default: Datacenter)
//	--insecure                     skip TLS verification (default: true)
//	--out        vsphere-report.json  output file (.json → JSON, else HTML)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"crypto/tls"
	"net"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/ssoadmin"
	"github.com/vmware/govmomi/sts"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"
)

// ── CLI helpers ───────────────────────────────────────────────────────────────

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ── Section model ─────────────────────────────────────────────────────────────

type section struct {
	Key       string
	Title     string
	Group     string
	Data      any
	Count     int
	Err       error
	Elapsed   time.Duration
	Collapsed bool
}

// ── Domain types ──────────────────────────────────────────────────────────────

type VCenterInfo struct {
	Name       string `json:"name"`
	FullName   string `json:"fullName"`
	Version    string `json:"version"`
	Build      string `json:"build"`
	APIVersion string `json:"apiVersion"`
	OSID       string `json:"osType"`
}

type DatacenterInfo struct {
	Name string `json:"name"`
	MOID string `json:"moid"`
}

type ClusterInfo struct {
	Name          string  `json:"name"`
	MOID          string  `json:"moid"`
	NumHosts      int32   `json:"numHosts"`
	NumCPUCores   int16   `json:"numCpuCores"`
	TotalCPUMHz   int32   `json:"totalCpuMHz"`
	TotalMemoryGB float64 `json:"totalMemoryGB"`
	HAEnabled     bool    `json:"haEnabled"`
	DRSEnabled    bool    `json:"drsEnabled"`
	DRSBehavior   string  `json:"drsBehavior"`
}

type HostInfo struct {
	Name          string  `json:"name"`
	MOID          string  `json:"moid"`
	Model         string  `json:"model"`
	Vendor        string  `json:"vendor"`
	CPUModel      string  `json:"cpuModel"`
	NumCPUPkgs    int16   `json:"numCpuPkgs"`
	NumCPUCores   int16   `json:"numCpuCores"`
	NumCPUThreads int16   `json:"numCpuThreads"`
	CPUMHz        int32   `json:"cpuMhz"`
	MemoryGB      float64 `json:"memoryGB"`
	ESXiVersion   string  `json:"esxiVersion"`
	ESXiBuild     string  `json:"esxiBuild"`
	PowerState    string  `json:"powerState"`
	ConnectionState string `json:"connectionState"`
	NumVMs        int     `json:"numVMs"`
}

type VMInfo struct {
	Name            string  `json:"name"`
	MOID            string  `json:"moid"`
	GuestID         string  `json:"guestId"`
	GuestFullName   string  `json:"guestFullName"`
	NumCPU          int32   `json:"numCpu"`
	MemoryMB        int32   `json:"memoryMB"`
	NumDisks        int32   `json:"numDisks"`
	NumNICs         int32   `json:"numNics"`
	PowerState      string  `json:"powerState"`
	IPAddress       string  `json:"ipAddress"`
	Hostname        string  `json:"hostname"`
	Host            string  `json:"host"`
	Datastore       string  `json:"datastore"`
	ToolsStatus     string  `json:"toolsStatus"`
	ToolsVersion    string  `json:"toolsVersion"`
	UsedDiskGB      float64 `json:"usedDiskGB"`
	ProvisionedGB   float64 `json:"provisionedGB"`
}

type DatastoreInfo struct {
	Name        string  `json:"name"`
	MOID        string  `json:"moid"`
	Type        string  `json:"type"`
	CapacityGB  float64 `json:"capacityGB"`
	FreeGB      float64 `json:"freeGB"`
	UsedPct     float64 `json:"usedPct"`
	URL         string  `json:"url"`
	Accessible  bool    `json:"accessible"`
	NumHosts    int     `json:"numHosts"`
	NumVMs      int     `json:"numVMs"`
}

type NetworkInfo struct {
	Name       string `json:"name"`
	MOID       string `json:"moid"`
	Type       string `json:"type"` // DistributedVirtualPortgroup | Network
	DVSName    string `json:"dvsName,omitempty"`
	VlanID     int32  `json:"vlanId"`
	NumPorts   int32  `json:"numPorts,omitempty"`
	NumHosts   int    `json:"numHosts"`
}

type ResourcePoolInfo struct {
	Name   string `json:"name"`
	MOID   string `json:"moid"`
	Parent string `json:"parent,omitempty"`
	NumVMs int    `json:"numVMs"`
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func bytesToGB(b int64) float64 {
	return math.Round(float64(b)/1e9*100) / 100
}

func mbToGB(mb int32) float64 {
	return math.Round(float64(mb)/1024*100) / 100
}

// ── Fetch functions ───────────────────────────────────────────────────────────

func fetchVCenter(ctx context.Context, client *govmomi.Client) ([]VCenterInfo, error) {
	about := client.Client.ServiceContent.About
	return []VCenterInfo{{
		Name:       about.Name,
		FullName:   about.FullName,
		Version:    about.Version,
		Build:      about.Build,
		APIVersion: about.ApiVersion,
		OSID:       about.OsType,
	}}, nil
}

func fetchDatacenters(ctx context.Context, finder *find.Finder, client *govmomi.Client) ([]DatacenterInfo, error) {
	dcs, err := finder.DatacenterList(ctx, "*")
	if err != nil {
		return nil, err
	}
	var out []DatacenterInfo
	for _, dc := range dcs {
		out = append(out, DatacenterInfo{
			Name: dc.Name(),
			MOID: dc.Reference().Value,
		})
	}
	return out, nil
}

func fetchClusters(ctx context.Context, finder *find.Finder, pc *property.Collector) ([]ClusterInfo, error) {
	clusters, err := finder.ClusterComputeResourceList(ctx, "*")
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	var refs []types.ManagedObjectReference
	for _, c := range clusters {
		refs = append(refs, c.Reference())
	}

	var moClusters []mo.ClusterComputeResource
	err = pc.Retrieve(ctx, refs, []string{
		"name", "summary", "configuration", "host",
	}, &moClusters)
	if err != nil {
		return nil, err
	}

	var out []ClusterInfo
	for _, c := range moClusters {
		info := ClusterInfo{
			Name: c.Name,
			MOID: c.Reference().Value,
		}
		if s := c.Summary.GetComputeResourceSummary(); s != nil {
			info.NumCPUCores = s.NumCpuCores
			info.TotalCPUMHz = s.TotalCpu
			info.TotalMemoryGB = bytesToGB(s.TotalMemory)
		}
		if cs, ok := c.Summary.(*types.ClusterComputeResourceSummary); ok {
			info.NumHosts = cs.NumHosts
		}
		if c.Configuration.DasConfig.Enabled != nil {
			info.HAEnabled = *c.Configuration.DasConfig.Enabled
		}
		if c.Configuration.DrsConfig.Enabled != nil {
			info.DRSEnabled = *c.Configuration.DrsConfig.Enabled
			info.DRSBehavior = string(c.Configuration.DrsConfig.DefaultVmBehavior)
		}
		out = append(out, info)
	}
	return out, nil
}

func fetchHosts(ctx context.Context, finder *find.Finder, pc *property.Collector) ([]HostInfo, error) {
	hosts, err := finder.HostSystemList(ctx, "*")
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	var refs []types.ManagedObjectReference
	for _, h := range hosts {
		refs = append(refs, h.Reference())
	}

	var moHosts []mo.HostSystem
	err = pc.Retrieve(ctx, refs, []string{
		"summary", "hardware", "config", "vm",
	}, &moHosts)
	if err != nil {
		return nil, err
	}

	var out []HostInfo
	for _, h := range moHosts {
		info := HostInfo{
			MOID:   h.Reference().Value,
			NumVMs: len(h.Vm),
		}
		cfg := h.Summary.Config
		info.Name = cfg.Name
		p := cfg.Product
		info.ESXiVersion = p.Version
		info.ESXiBuild = p.Build
		if h.Summary.Hardware != nil {
			hw := h.Summary.Hardware
			info.Model = hw.Model
			info.Vendor = hw.Vendor
			info.CPUModel = hw.CpuModel
			info.NumCPUPkgs = hw.NumCpuPkgs
			info.NumCPUCores = hw.NumCpuCores
			info.NumCPUThreads = hw.NumCpuThreads
			info.CPUMHz = hw.CpuMhz
			info.MemoryGB = bytesToGB(hw.MemorySize)
		}
		info.PowerState = string(h.Summary.Runtime.PowerState)
		info.ConnectionState = string(h.Summary.Runtime.ConnectionState)
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func fetchVMs(ctx context.Context, finder *find.Finder, pc *property.Collector) ([]VMInfo, error) {
	vms, err := finder.VirtualMachineList(ctx, "*")
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	var refs []types.ManagedObjectReference
	for _, v := range vms {
		refs = append(refs, v.Reference())
	}

	var moVMs []mo.VirtualMachine
	err = pc.Retrieve(ctx, refs, []string{
		"summary", "guest", "datastore",
	}, &moVMs)
	if err != nil {
		return nil, err
	}

	var out []VMInfo
	for _, v := range moVMs {
		info := VMInfo{
			MOID: v.Reference().Value,
		}
		cfg := v.Summary.Config
		info.Name = cfg.Name
		info.GuestID = cfg.GuestId
		info.GuestFullName = cfg.GuestFullName
		info.NumCPU = cfg.NumCpu
		info.MemoryMB = cfg.MemorySizeMB
		info.NumDisks = cfg.NumVirtualDisks
		info.NumNICs = cfg.NumEthernetCards
		if v.Summary.Guest != nil {
			info.ToolsStatus = string(v.Summary.Guest.ToolsStatus)
			info.ToolsVersion = v.Summary.Guest.ToolsVersionStatus2
		}
		info.PowerState = string(v.Summary.Runtime.PowerState)
		if v.Summary.Runtime.Host != nil {
			info.Host = v.Summary.Runtime.Host.Value
		}
		if v.Guest != nil {
			info.IPAddress = v.Guest.IpAddress
			info.Hostname = v.Guest.HostName
		}
		if ss := v.Summary.Storage; ss != nil {
			info.UsedDiskGB = bytesToGB(ss.Committed)
			info.ProvisionedGB = bytesToGB(ss.Committed + ss.Uncommitted)
		}
		if len(v.Datastore) > 0 {
			info.Datastore = v.Datastore[0].Value
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func fetchDatastores(ctx context.Context, finder *find.Finder, pc *property.Collector) ([]DatastoreInfo, error) {
	dsList, err := finder.DatastoreList(ctx, "*")
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	var refs []types.ManagedObjectReference
	for _, ds := range dsList {
		refs = append(refs, ds.Reference())
	}

	var moDS []mo.Datastore
	err = pc.Retrieve(ctx, refs, []string{
		"summary", "host", "vm",
	}, &moDS)
	if err != nil {
		return nil, err
	}

	var out []DatastoreInfo
	for _, ds := range moDS {
		s := ds.Summary
		used := s.Capacity - s.FreeSpace
		usedPct := 0.0
		if s.Capacity > 0 {
			usedPct = math.Round(float64(used)/float64(s.Capacity)*1000) / 10
		}
		out = append(out, DatastoreInfo{
			Name:       s.Name,
			MOID:       ds.Reference().Value,
			Type:       s.Type,
			CapacityGB: bytesToGB(s.Capacity),
			FreeGB:     bytesToGB(s.FreeSpace),
			UsedPct:    usedPct,
			URL:        s.Url,
			Accessible: s.Accessible,
			NumHosts:   len(ds.Host),
			NumVMs:     len(ds.Vm),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func fetchNetworks(ctx context.Context, finder *find.Finder, pc *property.Collector) ([]NetworkInfo, error) {
	// Distributed port groups
	var out []NetworkInfo

	dvpgs, err := finder.NetworkList(ctx, "*")
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	for _, n := range dvpgs {
		ref := n.Reference()
		// Extract the leaf name from the inventory path
		invPath := n.GetInventoryPath()
		name := invPath
		if idx := strings.LastIndex(invPath, "/"); idx >= 0 {
			name = invPath[idx+1:]
		}
		info := NetworkInfo{
			Name: name,
			MOID: ref.Value,
			Type: ref.Type,
		}

		switch ref.Type {
		case "DistributedVirtualPortgroup":
			var mo mo.DistributedVirtualPortgroup
			if err := pc.RetrieveOne(ctx, ref, []string{"config", "host"}, &mo); err == nil {
				info.NumHosts = len(mo.Host)
				if mo.Config.DefaultPortConfig != nil {
					if vlan, ok := mo.Config.DefaultPortConfig.(*types.VMwareDVSPortSetting); ok {
						switch v := vlan.Vlan.(type) {
						case *types.VmwareDistributedVirtualSwitchVlanIdSpec:
							info.VlanID = v.VlanId
						}
					}
				}
				info.NumPorts = mo.Config.NumPorts
				if mo.Config.DistributedVirtualSwitch != nil {
					info.DVSName = mo.Config.DistributedVirtualSwitch.Value
				}
			}
		case "Network":
			var mo mo.Network
			if err := pc.RetrieveOne(ctx, ref, []string{"host"}, &mo); err == nil {
				info.NumHosts = len(mo.Host)
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func fetchResourcePools(ctx context.Context, finder *find.Finder, pc *property.Collector) ([]ResourcePoolInfo, error) {
	pools, err := finder.ResourcePoolList(ctx, "*")
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	var refs []types.ManagedObjectReference
	for _, p := range pools {
		refs = append(refs, p.Reference())
	}

	var moPools []mo.ResourcePool
	err = pc.Retrieve(ctx, refs, []string{"name", "parent", "vm"}, &moPools)
	if err != nil {
		return nil, err
	}

	var out []ResourcePoolInfo
	for _, p := range moPools {
		parent := ""
		if p.Parent != nil {
			parent = p.Parent.Value
		}
		out = append(out, ResourcePoolInfo{
			Name:   p.Name,
			MOID:   p.Reference().Value,
			Parent: parent,
			NumVMs: len(p.Vm),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

type LicenseInfo struct {
	Name       string `json:"name"`
	Key        string `json:"key"`
	EditionKey string `json:"editionKey"`
	Total      int32  `json:"total"`
	Used       int32  `json:"used"`
	CostUnit   string `json:"costUnit"`
}

type UserInfo struct {
	Name      string `json:"name"`
	Domain    string `json:"domain"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	Disabled  bool   `json:"disabled"`
	Locked    bool   `json:"locked"`
	Kind      string `json:"kind"` // "person" or "solution"
}

type GroupInfo struct {
	Name        string `json:"name"`
	Domain      string `json:"domain"`
	Description string `json:"description"`
}

type CertInfo struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	DNSNames     []string `json:"dnsNames,omitempty"`
	IPAddresses  []string `json:"ipAddresses,omitempty"`
	NotBefore    string `json:"notBefore"`
	NotAfter     string `json:"notAfter"`
	SerialNumber string `json:"serialNumber"`
	SHA256       string `json:"sha256Thumbprint"`
	SHA1         string `json:"sha1Thumbprint"`
	SelfSigned   bool   `json:"selfSigned"`
}

// ── Fetch: licenses ───────────────────────────────────────────────────────────

func fetchLicenses(ctx context.Context, client *govmomi.Client) ([]LicenseInfo, error) {
	lm := client.Client.ServiceContent.LicenseManager
	if lm == nil {
		return nil, nil
	}
	var mgr mo.LicenseManager
	err := property.DefaultCollector(client.Client).RetrieveOne(ctx, *lm, []string{"licenses"}, &mgr)
	if err != nil {
		return nil, err
	}
	var out []LicenseInfo
	for _, lic := range mgr.Licenses {
		out = append(out, LicenseInfo{
			Name:       lic.Name,
			Key:        lic.LicenseKey,
			EditionKey: lic.EditionKey,
			Total:      lic.Total,
			Used:       lic.Used,
			CostUnit:   lic.CostUnit,
		})
	}
	return out, nil
}

// ssoClient creates an ssoadmin.Client authenticated via an STS SAML token,
// which is required even when the main govmomi session is already authenticated.
func ssoClient(ctx context.Context, client *govmomi.Client, user *url.Userinfo) (*ssoadmin.Client, error) {
	sc, err := ssoadmin.NewClient(ctx, client.Client)
	if err != nil {
		return nil, fmt.Errorf("ssoadmin.NewClient: %w", err)
	}

	tokens, err := sts.NewClient(ctx, client.Client)
	if err != nil {
		return nil, fmt.Errorf("sts.NewClient: %w", err)
	}
	signer, err := tokens.Issue(ctx, sts.TokenRequest{
		Certificate: client.Client.Certificate(),
		Userinfo:    user,
	})
	if err != nil {
		return nil, fmt.Errorf("sts.Issue: %w", err)
	}

	header := soap.Header{Security: signer}
	if err := sc.Login(sc.WithHeader(ctx, header)); err != nil {
		return nil, fmt.Errorf("ssoadmin login: %w", err)
	}
	return sc, nil
}

// ── Fetch: SSO users & groups ─────────────────────────────────────────────────

func fetchUsers(ctx context.Context, client *govmomi.Client, user *url.Userinfo) ([]UserInfo, error) {
	sc, err := ssoClient(ctx, client, user)
	if err != nil {
		return nil, err
	}
	defer sc.Logout(ctx)

	persons, err := sc.FindPersonUsers(ctx, "")
	if err != nil {
		return nil, err
	}
	solutions, err := sc.FindSolutionUsers(ctx, "")
	if err != nil {
		return nil, err
	}

	var out []UserInfo
	for _, u := range persons {
		out = append(out, UserInfo{
			Name:      u.Id.Name,
			Domain:    u.Id.Domain,
			FirstName: u.Details.FirstName,
			LastName:  u.Details.LastName,
			Email:     u.Details.EmailAddress,
			Disabled:  u.Disabled,
			Locked:    u.Locked,
			Kind:      "person",
		})
	}
	for _, u := range solutions {
		out = append(out, UserInfo{
			Name:   u.Id.Name,
			Domain: u.Id.Domain,
			Kind:   "solution",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func fetchGroups(ctx context.Context, client *govmomi.Client, user *url.Userinfo) ([]GroupInfo, error) {
	sc, err := ssoClient(ctx, client, user)
	if err != nil {
		return nil, err
	}
	defer sc.Logout(ctx)

	groups, err := sc.FindGroups(ctx, "")
	if err != nil {
		return nil, err
	}

	var out []GroupInfo
	for _, g := range groups {
		out = append(out, GroupInfo{
			Name:        g.Id.Name,
			Domain:      g.Id.Domain,
			Description: g.Details.Description,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}


// ── Fetch: TLS certificates ───────────────────────────────────────────────────

func fetchCertificates(ctx context.Context, client *govmomi.Client, host string) ([]CertInfo, error) {
	// Derive host:port from the govmomi client URL
	addr := host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", addr, err)
	}
	defer conn.Close()

	var out []CertInfo
	for _, cert := range conn.ConnectionState().PeerCertificates {
		var ips []string
		for _, ip := range cert.IPAddresses {
			ips = append(ips, ip.String())
		}
		out = append(out, CertInfo{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			DNSNames:     cert.DNSNames,
			IPAddresses:  ips,
			NotBefore:    cert.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:     cert.NotAfter.UTC().Format(time.RFC3339),
			SerialNumber: cert.SerialNumber.String(),
			SHA256:       soap.ThumbprintSHA256(cert),
			SHA1:         soap.ThumbprintSHA1(cert),
			SelfSigned:   cert.Issuer.String() == cert.Subject.String(),
		})
	}
	return out, nil
}

func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
}

// ── Parallel fetch orchestration ──────────────────────────────────────────────

func runSections(ctx context.Context, client *govmomi.Client, dcName string, host string, userinfo *url.Userinfo) []section {
	finder := find.NewFinder(client.Client, true)
	pc := property.DefaultCollector(client.Client)

	// Set datacenter scope
	dc, err := finder.Datacenter(ctx, dcName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: datacenter %q not found: %v\n", dcName, err)
	} else {
		finder.SetDatacenter(dc)
	}

	type fetcher struct {
		key       string
		title     string
		group     string
		collapsed bool
		fn        func() (any, int, error)
	}

	fetchers := []fetcher{
		{
			key: "vcenter", title: "vCenter Server", group: "Infrastructure",
			fn: func() (any, int, error) {
				d, err := fetchVCenter(ctx, client)
				return d, len(d), err
			},
		},
		{
			key: "datacenters", title: "Datacenters", group: "Infrastructure",
			fn: func() (any, int, error) {
				d, err := fetchDatacenters(ctx, finder, client)
				return d, len(d), err
			},
		},
		{
			key: "clusters", title: "Clusters", group: "Infrastructure",
			fn: func() (any, int, error) {
				d, err := fetchClusters(ctx, finder, pc)
				return d, len(d), err
			},
		},
		{
			key: "hosts", title: "ESXi Hosts", group: "Compute",
			fn: func() (any, int, error) {
				d, err := fetchHosts(ctx, finder, pc)
				return d, len(d), err
			},
		},
		{
			key: "vms", title: "Virtual Machines", group: "Compute", collapsed: true,
			fn: func() (any, int, error) {
				d, err := fetchVMs(ctx, finder, pc)
				return d, len(d), err
			},
		},
		{
			key: "datastores", title: "Datastores", group: "Storage",
			fn: func() (any, int, error) {
				d, err := fetchDatastores(ctx, finder, pc)
				return d, len(d), err
			},
		},
		{
			key: "networks", title: "Networks / Port Groups", group: "Networking",
			fn: func() (any, int, error) {
				d, err := fetchNetworks(ctx, finder, pc)
				return d, len(d), err
			},
		},
		{
			key: "resource_pools", title: "Resource Pools", group: "Compute",
			fn: func() (any, int, error) {
				d, err := fetchResourcePools(ctx, finder, pc)
				return d, len(d), err
			},
		},
		{
			key: "licenses", title: "Licenses", group: "Infrastructure",
			fn: func() (any, int, error) {
				d, err := fetchLicenses(ctx, client)
				return d, len(d), err
			},
		},
		{
			key: "users", title: "SSO Users", group: "Identity",
			fn: func() (any, int, error) {
				d, err := fetchUsers(ctx, client, userinfo)
				return d, len(d), err
			},
		},
		{
			key: "groups", title: "SSO Groups", group: "Identity",
			fn: func() (any, int, error) {
				d, err := fetchGroups(ctx, client, userinfo)
				return d, len(d), err
			},
		},
		{
			key: "certificates", title: "TLS Certificates", group: "Identity",
			fn: func() (any, int, error) {
				d, err := fetchCertificates(ctx, client, host)
				return d, len(d), err
			},
		},
	}

	results := make([]section, len(fetchers))
	var wg sync.WaitGroup
	for i, f := range fetchers {
		wg.Add(1)
		go func(idx int, f fetcher) {
			defer wg.Done()
			start := time.Now()
			data, count, err := f.fn()
			results[idx] = section{
				Key:       f.key,
				Title:     f.title,
				Group:     f.group,
				Data:      data,
				Count:     count,
				Err:       err,
				Elapsed:   time.Since(start),
				Collapsed: f.collapsed,
			}
		}(i, f)
	}
	wg.Wait()
	return results
}

// ── JSON output ───────────────────────────────────────────────────────────────

func writeJSON(sections []section, outFile string) error {
	report := map[string]any{
		"generated": time.Now().UTC().Format(time.RFC3339),
		"sections":  map[string]any{},
	}
	sec := report["sections"].(map[string]any)
	for _, s := range sections {
		if s.Err != nil {
			sec[s.Key] = map[string]any{"error": s.Err.Error()}
		} else {
			sec[s.Key] = s.Data
		}
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outFile, b, 0o644)
}

// ── HTML output ───────────────────────────────────────────────────────────────

const htmlTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>vSphere Report</title>
<style>
  body{font-family:system-ui,sans-serif;margin:2rem;background:#f5f5f5;color:#222}
  h1{color:#1a5276}
  h2{color:#1f618d;margin-top:2rem;border-bottom:2px solid #aed6f1;padding-bottom:.3rem}
  h3{color:#2874a6;margin:.5rem 0}
  details{background:#fff;border:1px solid #d6eaf8;border-radius:6px;margin:.5rem 0;padding:.5rem 1rem}
  summary{cursor:pointer;font-weight:600;font-size:.95rem}
  .badge{background:#2e86c1;color:#fff;border-radius:10px;padding:.1rem .5rem;font-size:.8rem;margin-left:.4rem}
  .err{color:#c0392b;font-style:italic}
  .meta{color:#888;font-size:.8rem;margin-left:.5rem}
  table{border-collapse:collapse;width:100%;margin:.5rem 0;font-size:.85rem}
  th{background:#2e86c1;color:#fff;text-align:left;padding:.3rem .5rem}
  td{padding:.25rem .5rem;border-bottom:1px solid #eaf2ff}
  tr:nth-child(even) td{background:#eaf2ff}
  .poweredOn{color:#1e8449} .poweredOff{color:#922b21} .suspended{color:#d4ac0d}
</style>
</head>
<body>
<h1>vSphere Inventory Report</h1>
<p class="meta">Generated: {{.Generated}}</p>

{{range .Groups}}
<h2>{{.Name}}</h2>
{{range .Sections}}
<details{{if not .Collapsed}} open{{end}}>
  <summary>{{.Title}} <span class="badge">{{.Count}}</span> <span class="meta">{{.Elapsed}}</span></summary>
  {{if .Err}}<p class="err">Error: {{.Err}}</p>
  {{else}}{{.TableHTML}}
  {{end}}
</details>
{{end}}
{{end}}
</body>
</html>`

type groupData struct {
	Name     string
	Sections []sectionHTML
}

type sectionHTML struct {
	Title     string
	Count     int
	Elapsed   string
	Err       error
	TableHTML template.HTML
	Collapsed bool
}

func toTableHTML(data any) template.HTML {
	if data == nil {
		return "<p><em>No data</em></p>"
	}
	b, _ := json.Marshal(data)
	var rows []map[string]any
	if err := json.Unmarshal(b, &rows); err != nil || len(rows) == 0 {
		return template.HTML("<pre>" + template.HTMLEscapeString(string(b)) + "</pre>")
	}
	// collect ordered keys from first row
	keys := make([]string, 0)
	seen := map[string]bool{}
	for _, row := range rows {
		for k := range row {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString("<table><tr>")
	for _, k := range keys {
		sb.WriteString("<th>" + template.HTMLEscapeString(k) + "</th>")
	}
	sb.WriteString("</tr>")
	for _, row := range rows {
		sb.WriteString("<tr>")
		for _, k := range keys {
			v := fmt.Sprintf("%v", row[k])
			cls := ""
			if k == "powerState" {
				cls = " class=\"" + v + "\""
			}
			sb.WriteString("<td" + cls + ">" + template.HTMLEscapeString(v) + "</td>")
		}
		sb.WriteString("</tr>")
	}
	sb.WriteString("</table>")
	return template.HTML(sb.String())
}

func writeHTML(sections []section, generated string, outFile string) error {
	groupOrder := []string{"Infrastructure", "Compute", "Storage", "Networking", "Identity"}
	groupMap := map[string][]sectionHTML{}

	for _, s := range sections {
		sh := sectionHTML{
			Title:     s.Title,
			Count:     s.Count,
			Elapsed:   s.Elapsed.Truncate(time.Millisecond).String(),
			Err:       s.Err,
			Collapsed: s.Collapsed,
		}
		if s.Err == nil {
			sh.TableHTML = toTableHTML(s.Data)
		}
		groupMap[s.Group] = append(groupMap[s.Group], sh)
	}

	var groups []groupData
	for _, g := range groupOrder {
		if secs, ok := groupMap[g]; ok {
			groups = append(groups, groupData{Name: g, Sections: secs})
		}
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"not": func(b bool) bool { return !b },
	}).Parse(htmlTmpl)
	if err != nil {
		return err
	}

	f, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, map[string]any{
		"Generated": generated,
		"Groups":    groups,
	})
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	host := flag.String("host", envOr("VSPHERE_HOST", ""), "vCenter host/IP")
	user := flag.String("user", envOr("VSPHERE_USER", "administrator@vsphere.local"), "username")
	pass := flag.String("password", envOr("VSPHERE_PASSWORD", ""), "password")
	dc := flag.String("dc", envOr("VSPHERE_DC", "Datacenter"), "datacenter name")
	insecure := flag.Bool("insecure", true, "skip TLS verification")
	outFile := flag.String("out", "vsphere-report.json", "output file (.json → JSON, else HTML)")
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "error: --host / VSPHERE_HOST required")
		os.Exit(1)
	}
	if *pass == "" {
		fmt.Fprintln(os.Stderr, "error: --password / VSPHERE_PASSWORD required")
		os.Exit(1)
	}

	ctx := context.Background()

	u := &url.URL{
		Scheme: "https",
		Host:   *host,
		Path:   "/sdk",
	}
	u.User = url.UserPassword(*user, *pass)

	fmt.Printf("connecting to vCenter %s ...\n", *host)
	client, err := govmomi.NewClient(ctx, u, *insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect error: %v\n", err)
		os.Exit(1)
	}
	defer client.Logout(ctx)

	fmt.Printf("fetching inventory (datacenter: %s) ...\n", *dc)
	start := time.Now()
	sections := runSections(ctx, client, *dc, *host, u.User)
	fmt.Printf("fetched in %s\n", time.Since(start).Truncate(time.Millisecond))

	for _, s := range sections {
		if s.Err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠  %s: %v\n", s.Title, s.Err)
		} else {
			fmt.Printf("  ✓  %-30s %d items\n", s.Title, s.Count)
		}
	}

	generated := time.Now().UTC().Format(time.RFC3339)
	ext := strings.ToLower(filepath.Ext(*outFile))

	if ext == ".json" {
		if err := writeJSON(sections, *outFile); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := writeHTML(sections, generated, *outFile); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("report written to %s\n", *outFile)
}
