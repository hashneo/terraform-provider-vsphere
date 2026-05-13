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

// ── ESXi host detail types ────────────────────────────────────────────────────

type HostPNIC struct {
	Host     string `json:"host"`
	Device   string `json:"device"`
	MAC      string `json:"mac"`
	SpeedMb  int32  `json:"speedMb"`
	Duplex   bool   `json:"fullDuplex"`
	Driver   string `json:"driver"`
	LinkUp   bool   `json:"linkUp"`
}

type HostVMKNIC struct {
	Host        string `json:"host"`
	Device      string `json:"device"`
	IPAddress   string `json:"ipAddress"`
	SubnetMask  string `json:"subnetMask"`
	MACAddress  string `json:"macAddress"`
	MTU         int32  `json:"mtu"`
	Portgroup   string `json:"portgroup"`
	VDS         string `json:"vds,omitempty"`
	Services    string `json:"services"` // management, vmotion, vSAN, etc.
}

type HostHBA struct {
	Host   string `json:"host"`
	Device string `json:"device"`
	Driver string `json:"driver"`
	Type   string `json:"type"`
	IQN    string `json:"iqn,omitempty"`
	Status string `json:"status"`
}

type HostService struct {
	Host    string `json:"host"`
	Key     string `json:"key"`
	Label   string `json:"label"`
	Policy  string `json:"policy"`
	Running bool   `json:"running"`
}

type HostFirewallRule struct {
	Host    string `json:"host"`
	Key     string `json:"key"`
	Label   string `json:"label"`
	Enabled bool   `json:"enabled"`
}

type HostPhysDisk struct {
	Host        string  `json:"host"`
	Device      string  `json:"device"`
	DisplayName string  `json:"displayName"`
	Vendor      string  `json:"vendor"`
	Model       string  `json:"model"`
	SerialNum   string  `json:"serialNumber"`
	SizeGB      float64 `json:"sizeGB"`
	SSD         bool    `json:"ssd"`
}

type HostNetConfig struct {
	Host     string   `json:"host"`
	Hostname string   `json:"hostname"`
	Domain   string   `json:"domain"`
	DNS      []string `json:"dnsServers"`
	NTP      []string `json:"ntpServers"`
	Lockdown string   `json:"lockdownMode"`
}

// ── Fetch: ESXi per-host detail ───────────────────────────────────────────────

func fetchHostDetail(ctx context.Context, finder *find.Finder, pc *property.Collector) (
	pnics []HostPNIC,
	vmknics []HostVMKNIC,
	hbas []HostHBA,
	services []HostService,
	fwRules []HostFirewallRule,
	physDisks []HostPhysDisk,
	netCfgs []HostNetConfig,
	err error,
) {
	hosts, err := finder.HostSystemList(ctx, "*")
	if err != nil {
		if isNotFound(err) {
			err = nil
		}
		return
	}

	var refs []types.ManagedObjectReference
	for _, h := range hosts {
		refs = append(refs, h.Reference())
	}

	var moHosts []mo.HostSystem
	if err = pc.Retrieve(ctx, refs, []string{"summary", "config"}, &moHosts); err != nil {
		return
	}

	for _, h := range moHosts {
		hostName := h.Summary.Config.Name
		cfg := h.Config
		if cfg == nil {
			continue
		}

		// ── Network config (DNS / NTP / lockdown) ──────────────────────────
		nc := HostNetConfig{
			Host:     hostName,
			Lockdown: string(cfg.LockdownMode),
		}
		if cfg.Network != nil {
			if dns := cfg.Network.DnsConfig; dns != nil {
				dnsBase := dns.GetHostDnsConfig()
				nc.Hostname = dnsBase.HostName
				nc.Domain = dnsBase.DomainName
				nc.DNS = dnsBase.Address
			}
		}
		if cfg.DateTimeInfo != nil && cfg.DateTimeInfo.NtpConfig != nil {
			nc.NTP = cfg.DateTimeInfo.NtpConfig.Server
		}
		netCfgs = append(netCfgs, nc)

		// ── Physical NICs ──────────────────────────────────────────────────
		if cfg.Network != nil {
			for _, pnic := range cfg.Network.Pnic {
				p := HostPNIC{
					Host:   hostName,
					Device: pnic.Device,
					MAC:    pnic.Mac,
					Driver: pnic.Driver,
				}
				if pnic.LinkSpeed != nil {
					p.SpeedMb = pnic.LinkSpeed.SpeedMb
					p.Duplex = pnic.LinkSpeed.Duplex
					p.LinkUp = true
				}
				pnics = append(pnics, p)
			}

			// ── VMkernel NICs ──────────────────────────────────────────────
			// Build a set of enabled services per vmknic
			vmkServices := map[string][]string{}
			if cfg.VirtualNicManagerInfo != nil {
				for _, netCfg := range cfg.VirtualNicManagerInfo.NetConfig {
					svcType := string(netCfg.NicType)
					for _, sel := range netCfg.SelectedVnic {
						vmkServices[sel] = append(vmkServices[sel], svcType)
					}
				}
			}

			for _, vnic := range cfg.Network.Vnic {
				v := HostVMKNIC{
					Host:      hostName,
					Device:    vnic.Device,
					Portgroup: vnic.Portgroup,
				}
				if vnic.Spec.Ip != nil {
					v.IPAddress = vnic.Spec.Ip.IpAddress
					v.SubnetMask = vnic.Spec.Ip.SubnetMask
				}
				v.MACAddress = vnic.Spec.Mac
				v.MTU = vnic.Spec.Mtu
				if vnic.Spec.DistributedVirtualPort != nil {
					v.VDS = vnic.Spec.DistributedVirtualPort.SwitchUuid
				}
				// match by device key (vnic.Key looks like "VirtualNic:vmk0")
				svcs := vmkServices[vnic.Key]
				v.Services = strings.Join(svcs, ",")
				vmknics = append(vmknics, v)
			}
		}

		// ── HBAs ──────────────────────────────────────────────────────────
		for _, hba := range cfg.StorageDevice.HostBusAdapter {
			h := HostHBA{
				Host:   hostName,
				Status: string(hba.GetHostHostBusAdapter().Status),
				Device: hba.GetHostHostBusAdapter().Device,
				Driver: hba.GetHostHostBusAdapter().Driver,
				Type:   fmt.Sprintf("%T", hba),
			}
			// trim the govmomi type prefix for readability
			if idx := strings.LastIndex(h.Type, "."); idx >= 0 {
				h.Type = h.Type[idx+1:]
			}
			// iSCSI software adapter has an IQN
			if iscsi, ok := hba.(*types.HostInternetScsiHba); ok {
				h.IQN = iscsi.IScsiName
			}
			hbas = append(hbas, h)
		}

		// ── Physical disks ─────────────────────────────────────────────────
		for _, lun := range cfg.StorageDevice.ScsiLun {
			disk, ok := lun.(*types.HostScsiDisk)
			if !ok {
				continue
			}
			base := disk.GetScsiLun()
			sizeGB := bytesToGB(int64(disk.Capacity.Block) * int64(disk.Capacity.BlockSize))
			physDisks = append(physDisks, HostPhysDisk{
				Host:        hostName,
				Device:      base.DeviceName,
				DisplayName: base.DisplayName,
				Vendor:      strings.TrimSpace(base.Vendor),
				Model:       strings.TrimSpace(base.Model),
				SerialNum:   base.SerialNumber,
				SizeGB:      sizeGB,
				SSD:         disk.Ssd != nil && *disk.Ssd,
			})
		}

		// ── Services ──────────────────────────────────────────────────────
		if cfg.Service != nil {
			for _, svc := range cfg.Service.Service {
				services = append(services, HostService{
					Host:    hostName,
					Key:     svc.Key,
					Label:   svc.Label,
					Policy:  svc.Policy,
					Running: svc.Running,
				})
			}
		}

		// ── Firewall rules ─────────────────────────────────────────────────
		if cfg.Firewall != nil {
			for _, rule := range cfg.Firewall.Ruleset {
				fwRules = append(fwRules, HostFirewallRule{
					Host:    hostName,
					Key:     rule.Key,
					Label:   rule.Label,
					Enabled: rule.Enabled,
				})
			}
		}
	}
	return
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

	// ── ESXi host detail (one API round-trip, split into 7 sections) ──────────
	// Fetch synchronously so all sub-sections share the same result.
	var (
		hPNICs    []HostPNIC
		hVMKNICs  []HostVMKNIC
		hHBAs     []HostHBA
		hServices []HostService
		hFWRules  []HostFirewallRule
		hDisks    []HostPhysDisk
		hNetCfgs  []HostNetConfig
		hDetailErr error
	)
	hPNICs, hVMKNICs, hHBAs, hServices, hFWRules, hDisks, hNetCfgs, hDetailErr =
		fetchHostDetail(ctx, finder, pc)

	detailSections := []fetcher{
		{key: "host_net_config", title: "ESXi Network Config (DNS/NTP)", group: "ESXi Detail",
			fn: func() (any, int, error) { return hNetCfgs, len(hNetCfgs), hDetailErr }},
		{key: "host_pnics", title: "ESXi Physical NICs", group: "ESXi Detail",
			fn: func() (any, int, error) { return hPNICs, len(hPNICs), hDetailErr }},
		{key: "host_vmknics", title: "ESXi VMkernel NICs", group: "ESXi Detail",
			fn: func() (any, int, error) { return hVMKNICs, len(hVMKNICs), hDetailErr }},
		{key: "host_hbas", title: "ESXi HBAs", group: "ESXi Detail",
			fn: func() (any, int, error) { return hHBAs, len(hHBAs), hDetailErr }},
		{key: "host_disks", title: "ESXi Physical Disks", group: "ESXi Detail", collapsed: true,
			fn: func() (any, int, error) { return hDisks, len(hDisks), hDetailErr }},
		{key: "host_services", title: "ESXi Services", group: "ESXi Detail", collapsed: true,
			fn: func() (any, int, error) { return hServices, len(hServices), hDetailErr }},
		{key: "host_firewall", title: "ESXi Firewall Rules", group: "ESXi Detail", collapsed: true,
			fn: func() (any, int, error) { return hFWRules, len(hFWRules), hDetailErr }},
	}
	fetchers = append(fetchers, detailSections...)

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
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vSphere Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:13px;background:#f5f6fa;color:#222}
header{background:#1a1a2e;color:#fff;padding:16px 24px;display:flex;align-items:center;gap:24px;flex-wrap:wrap}
header h1{font-size:18px;font-weight:600;letter-spacing:.5px}
.header-meta{font-size:12px;color:#aab}
.header-counts{display:flex;gap:12px;margin-left:auto;flex-wrap:wrap}
.hcount{background:#ffffff22;border-radius:12px;padding:3px 10px;font-size:12px}
.layout{display:flex;min-height:calc(100vh - 56px)}
nav{width:200px;min-width:200px;background:#fff;border-right:1px solid #e2e8f0;padding:16px 0;position:sticky;top:0;height:calc(100vh - 56px);overflow-y:auto}
nav .group-label{padding:10px 16px 4px;font-size:10px;font-weight:700;text-transform:uppercase;color:#94a3b8;letter-spacing:.8px}
nav a{display:block;padding:6px 16px 6px 20px;color:#475569;text-decoration:none;font-size:12px;border-left:2px solid transparent;transition:all .15s}
nav a:hover{background:#f1f5f9;color:#1a1a2e;border-left-color:#6366f1}
main{flex:1;padding:20px 24px;min-width:0}
.section-card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;margin-bottom:16px;overflow:hidden}
details>summary{list-style:none;padding:12px 16px;cursor:pointer;display:flex;align-items:center;gap:8px;user-select:none;background:#fff;border-bottom:1px solid transparent}
details>summary::-webkit-details-marker{display:none}
details[open]>summary{border-bottom-color:#e2e8f0;background:#f8fafc}
summary::before{content:"▶";font-size:10px;color:#94a3b8;transition:transform .2s;display:inline-block}
details[open]>summary::before{transform:rotate(90deg)}
.section-title{font-weight:600;font-size:13px;color:#1e293b}
.section-count{background:#e2e8f0;color:#64748b;border-radius:10px;padding:1px 8px;font-size:11px}
.section-count.error{background:#fee2e2;color:#dc2626}
.elapsed{margin-left:auto;font-size:11px;color:#94a3b8}
.group-badge{font-size:10px;padding:1px 7px;border-radius:8px;font-weight:500}
.badge-infra{background:#ede9fe;color:#7c3aed}
.badge-compute{background:#dbeafe;color:#2563eb}
.badge-stor{background:#d1fae5;color:#065f46}
.badge-net{background:#fef3c7;color:#92400e}
.badge-id{background:#fee2e2;color:#9f1239}
.badge-esxi{background:#e0f2fe;color:#0369a1}
.error-banner{padding:12px 16px;background:#fff7ed;border-left:3px solid #f97316;color:#9a3412;font-size:12px}
.table-wrap{overflow-x:auto;max-height:500px;overflow-y:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
thead th{position:sticky;top:0;background:#f8fafc;padding:8px 12px;text-align:left;font-weight:600;color:#64748b;border-bottom:2px solid #e2e8f0;white-space:nowrap}
tbody tr:nth-child(even){background:#f9fafb}
tbody tr:hover{background:#f1f5f9}
td{padding:6px 12px;color:#334155;vertical-align:top;border-bottom:1px solid #f1f5f9;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
td.wrap{white-space:normal;word-break:break-word}
td.mono{font-family:ui-monospace,monospace;font-size:11px}
.badge{display:inline-block;border-radius:10px;padding:1px 8px;font-size:11px;font-weight:500}
.green{background:#d1fae5;color:#065f46}
.red{background:#fee2e2;color:#991b1b}
.amber{background:#fef3c7;color:#92400e}
.grey{background:#f1f5f9;color:#64748b}
.kv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;padding:16px}
.kv-item{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:10px 12px}
.kv-label{font-size:10px;font-weight:600;text-transform:uppercase;color:#94a3b8;margin-bottom:2px}
.kv-value{font-size:13px;color:#1e293b;word-break:break-word}
</style>
</head>
<body>
<header>
  <h1>&#x2601; vSphere Report</h1>
  <span class="header-meta">Generated: {{.Generated}}</span>
  <span class="header-meta">Host: <code>{{.Host}}</code></span>
  <div class="header-counts">
    {{range .GroupCounts}}<span class="hcount">{{.Name}}: {{.Total}} items</span>{{end}}
  </div>
</header>
<div class="layout">
<nav>
  {{range .Groups}}
  <div class="group-label">{{.Name}}</div>
  {{range .Sections}}
  <a href="#{{.Key}}">{{.Title}}{{if .Err}} ⚠{{else if gt .Count 0}} ({{.Count}}){{end}}</a>
  {{end}}
  {{end}}
</nav>
<main>
{{range .Sections}}
<div class="section-card" id="{{.Key}}">
  <details{{if not .Collapsed}} open{{end}}>
    <summary>
      <span class="section-title">{{.Title}}</span>
      {{if .Err}}
        <span class="section-count error">error</span>
      {{else}}
        <span class="section-count">{{.Count}}</span>
      {{end}}
      <span class="group-badge {{.GroupClass}}">{{.Group}}</span>
      <span class="elapsed">{{.ElapsedStr}}</span>
    </summary>
    {{if .Err}}
      <div class="error-banner">&#9888; {{.Err}}</div>
    {{else}}
      {{.TableHTML}}
    {{end}}
  </details>
</div>
{{end}}
</main>
</div>
</body>
</html>`

// ── Template data types ───────────────────────────────────────────────────────

type templateData struct {
	Generated   string
	Host        string
	GroupCounts []groupCount
	Groups      []groupNav
	Sections    []sectionView
}

type groupCount struct {
	Name  string
	Total int
}

type groupNav struct {
	Name     string
	Sections []sectionView
}

type sectionView struct {
	Key        string
	Title      string
	Group      string
	GroupClass string
	Count      int
	Err        error
	ElapsedStr string
	Collapsed  bool
	TableHTML  template.HTML
}

func groupClass(group string) string {
	switch group {
	case "Infrastructure":
		return "badge-infra"
	case "Compute":
		return "badge-compute"
	case "Storage":
		return "badge-stor"
	case "Networking":
		return "badge-net"
	case "Identity":
		return "badge-id"
	case "ESXi Detail":
		return "badge-esxi"
	}
	return "grey"
}

func fmtElapsed(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// ── Table builder helpers ─────────────────────────────────────────────────────

func openTable() string  { return `<div class="table-wrap"><table><thead><tr>` }
func closeTable() string { return `</tbody></table></div>` }

func th(cols ...string) string {
	var sb strings.Builder
	for _, c := range cols {
		sb.WriteString(`<th>` + template.HTMLEscapeString(c) + `</th>`)
	}
	sb.WriteString(`</tr></thead><tbody>`)
	return sb.String()
}

func td(vals ...template.HTML) string {
	var sb strings.Builder
	sb.WriteString("<tr>")
	for _, v := range vals {
		sb.WriteString(`<td>` + string(v) + `</td>`)
	}
	sb.WriteString("</tr>")
	return sb.String()
}

func tdc(class string, val template.HTML) string {
	return `<td class="` + class + `">` + string(val) + `</td>`
}

func hstr(s string) template.HTML {
	if s == "" {
		return `<span style="color:#cbd5e1">—</span>`
	}
	return template.HTML(template.HTMLEscapeString(s))
}

func hbool(b bool) template.HTML {
	if b {
		return `<span class="badge green">yes</span>`
	}
	return `<span class="badge red">no</span>`
}

func hrunning(b bool) template.HTML {
	if b {
		return `<span class="badge green">running</span>`
	}
	return `<span class="badge grey">stopped</span>`
}

func hpower(s string) template.HTML {
	switch s {
	case "poweredOn":
		return `<span class="badge green">on</span>`
	case "poweredOff":
		return `<span class="badge red">off</span>`
	case "suspended":
		return `<span class="badge amber">suspended</span>`
	}
	return hstr(s)
}

func hfloat(f float64, unit string) template.HTML {
	return template.HTML(template.HTMLEscapeString(fmt.Sprintf("%.2f %s", f, unit)))
}

func hint(i interface{}) template.HTML {
	return template.HTML(template.HTMLEscapeString(fmt.Sprintf("%v", i)))
}

func hlist(ss []string) template.HTML {
	if len(ss) == 0 {
		return `<span style="color:#cbd5e1">—</span>`
	}
	return template.HTML(template.HTMLEscapeString(strings.Join(ss, ", ")))
}

func kvGrid(items [][2]string) template.HTML {
	var sb strings.Builder
	sb.WriteString(`<div class="kv-grid">`)
	for _, kv := range items {
		v := kv[1]
		if v == "" {
			v = "—"
		}
		sb.WriteString(`<div class="kv-item"><div class="kv-label">` +
			template.HTMLEscapeString(kv[0]) +
			`</div><div class="kv-value">` +
			template.HTMLEscapeString(v) +
			`</div></div>`)
	}
	sb.WriteString(`</div>`)
	return template.HTML(sb.String())
}

// ── Per-section table builders ────────────────────────────────────────────────

func vcenterTable(items []VCenterInfo) template.HTML {
	if len(items) == 0 {
		return ""
	}
	v := items[0]
	return kvGrid([][2]string{
		{"Name", v.Name},
		{"Full Name", v.FullName},
		{"Version", v.Version},
		{"Build", v.Build},
		{"API Version", v.APIVersion},
		{"OS Type", v.OSID},
	})
}

func datacentersTable(items []DatacenterInfo) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Name", "MOID"))
	for _, d := range items {
		sb.WriteString(td(hstr(d.Name), hstr(d.MOID)))
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func clustersTable(items []ClusterInfo) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Name", "Hosts", "CPU Cores", "Total CPU", "Total Memory", "HA", "DRS", "DRS Mode"))
	for _, c := range items {
		sb.WriteString("<tr>")
		sb.WriteString(tdc("", hstr(c.Name)))
		sb.WriteString(tdc("", hint(c.NumHosts)))
		sb.WriteString(tdc("", hint(c.NumCPUCores)))
		sb.WriteString(tdc("", template.HTML(fmt.Sprintf("%d MHz", c.TotalCPUMHz))))
		sb.WriteString(tdc("", hfloat(c.TotalMemoryGB, "GB")))
		sb.WriteString(tdc("", hbool(c.HAEnabled)))
		sb.WriteString(tdc("", hbool(c.DRSEnabled)))
		sb.WriteString(tdc("", hstr(c.DRSBehavior)))
		sb.WriteString("</tr>")
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func hostsTable(items []HostInfo) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Name", "Model", "CPU Model", "Pkgs", "Cores", "Threads", "MHz", "Memory", "ESXi Version", "Build", "Power", "State", "VMs"))
	for _, h := range items {
		sb.WriteString("<tr>")
		sb.WriteString(tdc("", hstr(h.Name)))
		sb.WriteString(tdc("", hstr(h.Model)))
		sb.WriteString(tdc("wrap", hstr(h.CPUModel)))
		sb.WriteString(tdc("", hint(h.NumCPUPkgs)))
		sb.WriteString(tdc("", hint(h.NumCPUCores)))
		sb.WriteString(tdc("", hint(h.NumCPUThreads)))
		sb.WriteString(tdc("", hint(h.CPUMHz)))
		sb.WriteString(tdc("", hfloat(h.MemoryGB, "GB")))
		sb.WriteString(tdc("", hstr(h.ESXiVersion)))
		sb.WriteString(tdc("mono", hstr(h.ESXiBuild)))
		sb.WriteString(tdc("", hpower(h.PowerState)))
		sb.WriteString(tdc("", hstr(h.ConnectionState)))
		sb.WriteString(tdc("", hint(h.NumVMs)))
		sb.WriteString("</tr>")
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func vmsTable(items []VMInfo) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Name", "Guest", "CPUs", "Memory", "Disks", "NICs", "Power", "IP Address", "Hostname", "Used Disk", "Provisioned", "Tools"))
	for _, v := range items {
		sb.WriteString("<tr>")
		sb.WriteString(tdc("", hstr(v.Name)))
		sb.WriteString(tdc("", hstr(v.GuestFullName)))
		sb.WriteString(tdc("", hint(v.NumCPU)))
		sb.WriteString(tdc("", template.HTML(fmt.Sprintf("%d MB", v.MemoryMB))))
		sb.WriteString(tdc("", hint(v.NumDisks)))
		sb.WriteString(tdc("", hint(v.NumNICs)))
		sb.WriteString(tdc("", hpower(v.PowerState)))
		sb.WriteString(tdc("mono", hstr(v.IPAddress)))
		sb.WriteString(tdc("", hstr(v.Hostname)))
		sb.WriteString(tdc("", hfloat(v.UsedDiskGB, "GB")))
		sb.WriteString(tdc("", hfloat(v.ProvisionedGB, "GB")))
		sb.WriteString(tdc("", hstr(v.ToolsStatus)))
		sb.WriteString("</tr>")
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func datastoresTable(items []DatastoreInfo) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Name", "Type", "Capacity", "Free", "Used %", "Accessible", "Hosts", "VMs"))
	for _, d := range items {
		usedPctBadge := template.HTML(fmt.Sprintf("%.1f%%", d.UsedPct))
		if d.UsedPct >= 90 {
			usedPctBadge = template.HTML(fmt.Sprintf(`<span class="badge red">%.1f%%</span>`, d.UsedPct))
		} else if d.UsedPct >= 75 {
			usedPctBadge = template.HTML(fmt.Sprintf(`<span class="badge amber">%.1f%%</span>`, d.UsedPct))
		}
		sb.WriteString("<tr>")
		sb.WriteString(tdc("", hstr(d.Name)))
		sb.WriteString(tdc("", hstr(d.Type)))
		sb.WriteString(tdc("", hfloat(d.CapacityGB, "GB")))
		sb.WriteString(tdc("", hfloat(d.FreeGB, "GB")))
		sb.WriteString(tdc("", usedPctBadge))
		sb.WriteString(tdc("", hbool(d.Accessible)))
		sb.WriteString(tdc("", hint(d.NumHosts)))
		sb.WriteString(tdc("", hint(d.NumVMs)))
		sb.WriteString("</tr>")
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func networksTable(items []NetworkInfo) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Name", "Type", "VLAN ID", "Ports", "Hosts", "DVS"))
	for _, n := range items {
		sb.WriteString("<tr>")
		sb.WriteString(tdc("", hstr(n.Name)))
		sb.WriteString(tdc("", hstr(n.Type)))
		vlan := template.HTML("—")
		if n.VlanID > 0 {
			vlan = hint(n.VlanID)
		}
		sb.WriteString(tdc("", vlan))
		sb.WriteString(tdc("", hint(n.NumPorts)))
		sb.WriteString(tdc("", hint(n.NumHosts)))
		sb.WriteString(tdc("mono", hstr(n.DVSName)))
		sb.WriteString("</tr>")
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func resourcePoolsTable(items []ResourcePoolInfo) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Name", "MOID", "Parent", "VMs"))
	for _, r := range items {
		sb.WriteString(td(hstr(r.Name), hstr(r.MOID), hstr(r.Parent), hint(r.NumVMs)))
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func licensesTable(items []LicenseInfo) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Name", "Edition", "Used", "Total", "Cost Unit"))
	for _, l := range items {
		sb.WriteString(td(hstr(l.Name), hstr(l.EditionKey), hint(l.Used), hint(l.Total), hstr(l.CostUnit)))
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func usersTable(items []UserInfo) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Name", "Domain", "Kind", "First Name", "Last Name", "Email", "Disabled", "Locked"))
	for _, u := range items {
		sb.WriteString("<tr>")
		sb.WriteString(tdc("", hstr(u.Name)))
		sb.WriteString(tdc("", hstr(u.Domain)))
		sb.WriteString(tdc("", hstr(u.Kind)))
		sb.WriteString(tdc("", hstr(u.FirstName)))
		sb.WriteString(tdc("", hstr(u.LastName)))
		sb.WriteString(tdc("", hstr(u.Email)))
		sb.WriteString(tdc("", hbool(u.Disabled)))
		sb.WriteString(tdc("", hbool(u.Locked)))
		sb.WriteString("</tr>")
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func groupsTable(items []GroupInfo) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Name", "Domain", "Description"))
	for _, g := range items {
		sb.WriteString(td(hstr(g.Name), hstr(g.Domain), hstr(g.Description)))
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func certsTable(items []CertInfo) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Subject", "Issuer", "DNS / IP SANs", "Not Before", "Not After", "Self-Signed", "SHA-256"))
	for _, c := range items {
		sans := append(c.DNSNames, c.IPAddresses...)
		sb.WriteString("<tr>")
		sb.WriteString(tdc("wrap", hstr(c.Subject)))
		sb.WriteString(tdc("wrap", hstr(c.Issuer)))
		sb.WriteString(tdc("wrap", hlist(sans)))
		sb.WriteString(tdc("mono", hstr(c.NotBefore)))
		sb.WriteString(tdc("mono", hstr(c.NotAfter)))
		sb.WriteString(tdc("", hbool(c.SelfSigned)))
		sb.WriteString(tdc("mono wrap", hstr(c.SHA256)))
		sb.WriteString("</tr>")
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func hostNetConfigTable(items []HostNetConfig) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Host", "Hostname", "Domain", "DNS Servers", "NTP Servers", "Lockdown"))
	for _, n := range items {
		sb.WriteString("<tr>")
		sb.WriteString(tdc("mono", hstr(n.Host)))
		sb.WriteString(tdc("", hstr(n.Hostname)))
		sb.WriteString(tdc("", hstr(n.Domain)))
		sb.WriteString(tdc("wrap", hlist(n.DNS)))
		sb.WriteString(tdc("wrap", hlist(n.NTP)))
		sb.WriteString(tdc("", hstr(n.Lockdown)))
		sb.WriteString("</tr>")
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func hostPNICsTable(items []HostPNIC) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Host", "Device", "MAC", "Speed (Mb)", "Full Duplex", "Driver", "Link Up"))
	for _, n := range items {
		sb.WriteString("<tr>")
		sb.WriteString(tdc("mono", hstr(n.Host)))
		sb.WriteString(tdc("", hstr(n.Device)))
		sb.WriteString(tdc("mono", hstr(n.MAC)))
		sb.WriteString(tdc("", hint(n.SpeedMb)))
		sb.WriteString(tdc("", hbool(n.Duplex)))
		sb.WriteString(tdc("", hstr(n.Driver)))
		sb.WriteString(tdc("", hbool(n.LinkUp)))
		sb.WriteString("</tr>")
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func hostVMKNICsTable(items []HostVMKNIC) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Host", "Device", "IP Address", "Subnet Mask", "MAC", "MTU", "Services", "DVS"))
	for _, n := range items {
		sb.WriteString("<tr>")
		sb.WriteString(tdc("mono", hstr(n.Host)))
		sb.WriteString(tdc("", hstr(n.Device)))
		sb.WriteString(tdc("mono", hstr(n.IPAddress)))
		sb.WriteString(tdc("mono", hstr(n.SubnetMask)))
		sb.WriteString(tdc("mono", hstr(n.MACAddress)))
		sb.WriteString(tdc("", hint(n.MTU)))
		sb.WriteString(tdc("", hstr(n.Services)))
		sb.WriteString(tdc("mono wrap", hstr(n.VDS)))
		sb.WriteString("</tr>")
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func hostHBAsTable(items []HostHBA) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Host", "Device", "Type", "Driver", "Status", "IQN"))
	for _, h := range items {
		sb.WriteString("<tr>")
		sb.WriteString(tdc("mono", hstr(h.Host)))
		sb.WriteString(tdc("", hstr(h.Device)))
		sb.WriteString(tdc("", hstr(h.Type)))
		sb.WriteString(tdc("", hstr(h.Driver)))
		sb.WriteString(tdc("", hstr(h.Status)))
		sb.WriteString(tdc("mono wrap", hstr(h.IQN)))
		sb.WriteString("</tr>")
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func hostDisksTable(items []HostPhysDisk) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Host", "Display Name", "Vendor", "Model", "Size", "SSD"))
	for _, d := range items {
		sb.WriteString("<tr>")
		sb.WriteString(tdc("mono", hstr(d.Host)))
		sb.WriteString(tdc("wrap", hstr(d.DisplayName)))
		sb.WriteString(tdc("", hstr(d.Vendor)))
		sb.WriteString(tdc("", hstr(d.Model)))
		sb.WriteString(tdc("", hfloat(d.SizeGB, "GB")))
		sb.WriteString(tdc("", hbool(d.SSD)))
		sb.WriteString("</tr>")
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func hostServicesTable(items []HostService) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Host", "Key", "Label", "Policy", "Running"))
	for _, s := range items {
		sb.WriteString("<tr>")
		sb.WriteString(tdc("mono", hstr(s.Host)))
		sb.WriteString(tdc("mono", hstr(s.Key)))
		sb.WriteString(tdc("", hstr(s.Label)))
		sb.WriteString(tdc("", hstr(s.Policy)))
		sb.WriteString(tdc("", hrunning(s.Running)))
		sb.WriteString("</tr>")
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

func hostFirewallTable(items []HostFirewallRule) template.HTML {
	var sb strings.Builder
	sb.WriteString(openTable())
	sb.WriteString(th("Host", "Key", "Label", "Enabled"))
	for _, r := range items {
		sb.WriteString("<tr>")
		sb.WriteString(tdc("mono", hstr(r.Host)))
		sb.WriteString(tdc("mono", hstr(r.Key)))
		sb.WriteString(tdc("", hstr(r.Label)))
		sb.WriteString(tdc("", hbool(r.Enabled)))
		sb.WriteString("</tr>")
	}
	sb.WriteString(closeTable())
	return template.HTML(sb.String())
}

// ── Dispatch: key → typed table builder ──────────────────────────────────────

func buildTableHTML(s section) template.HTML {
	if s.Data == nil {
		return `<div style="padding:12px 16px;color:#94a3b8;font-size:12px">No data.</div>`
	}
	switch s.Key {
	case "vcenter":
		if v, ok := s.Data.([]VCenterInfo); ok {
			return vcenterTable(v)
		}
	case "datacenters":
		if v, ok := s.Data.([]DatacenterInfo); ok {
			return datacentersTable(v)
		}
	case "clusters":
		if v, ok := s.Data.([]ClusterInfo); ok {
			return clustersTable(v)
		}
	case "hosts":
		if v, ok := s.Data.([]HostInfo); ok {
			return hostsTable(v)
		}
	case "vms":
		if v, ok := s.Data.([]VMInfo); ok {
			return vmsTable(v)
		}
	case "datastores":
		if v, ok := s.Data.([]DatastoreInfo); ok {
			return datastoresTable(v)
		}
	case "networks":
		if v, ok := s.Data.([]NetworkInfo); ok {
			return networksTable(v)
		}
	case "resource_pools":
		if v, ok := s.Data.([]ResourcePoolInfo); ok {
			return resourcePoolsTable(v)
		}
	case "licenses":
		if v, ok := s.Data.([]LicenseInfo); ok {
			return licensesTable(v)
		}
	case "users":
		if v, ok := s.Data.([]UserInfo); ok {
			return usersTable(v)
		}
	case "groups":
		if v, ok := s.Data.([]GroupInfo); ok {
			return groupsTable(v)
		}
	case "certificates":
		if v, ok := s.Data.([]CertInfo); ok {
			return certsTable(v)
		}
	case "host_net_config":
		if v, ok := s.Data.([]HostNetConfig); ok {
			return hostNetConfigTable(v)
		}
	case "host_pnics":
		if v, ok := s.Data.([]HostPNIC); ok {
			return hostPNICsTable(v)
		}
	case "host_vmknics":
		if v, ok := s.Data.([]HostVMKNIC); ok {
			return hostVMKNICsTable(v)
		}
	case "host_hbas":
		if v, ok := s.Data.([]HostHBA); ok {
			return hostHBAsTable(v)
		}
	case "host_disks":
		if v, ok := s.Data.([]HostPhysDisk); ok {
			return hostDisksTable(v)
		}
	case "host_services":
		if v, ok := s.Data.([]HostService); ok {
			return hostServicesTable(v)
		}
	case "host_firewall":
		if v, ok := s.Data.([]HostFirewallRule); ok {
			return hostFirewallTable(v)
		}
	}
	return `<div style="padding:12px 16px;color:#94a3b8;font-size:12px">No renderer for this section.</div>`
}

// ── writeHTML ─────────────────────────────────────────────────────────────────

func writeHTML(sections []section, generated string, host string, outFile string) error {
	groupOrder := []string{"Infrastructure", "Compute", "Storage", "Networking", "Identity", "ESXi Detail"}

	// Build flat list of sectionViews keyed by group
	groupMap := map[string][]sectionView{}
	allViews := []sectionView{}

	for _, s := range sections {
		sv := sectionView{
			Key:        s.Key,
			Title:      s.Title,
			Group:      s.Group,
			GroupClass: groupClass(s.Group),
			Count:      s.Count,
			Err:        s.Err,
			ElapsedStr: fmtElapsed(s.Elapsed),
			Collapsed:  s.Collapsed,
		}
		if s.Err == nil {
			sv.TableHTML = buildTableHTML(s)
		}
		groupMap[s.Group] = append(groupMap[s.Group], sv)
		allViews = append(allViews, sv)
	}

	// Nav groups
	var navGroups []groupNav
	for _, g := range groupOrder {
		if secs, ok := groupMap[g]; ok {
			navGroups = append(navGroups, groupNav{Name: g, Sections: secs})
		}
	}

	// Header counts per group
	var groupCounts []groupCount
	for _, g := range groupOrder {
		total := 0
		for _, sv := range groupMap[g] {
			total += sv.Count
		}
		if total > 0 {
			groupCounts = append(groupCounts, groupCount{Name: g, Total: total})
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

	return tmpl.Execute(f, templateData{
		Generated:   generated,
		Host:        host,
		GroupCounts: groupCounts,
		Groups:      navGroups,
		Sections:    allViews,
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
		if err := writeHTML(sections, generated, *host, *outFile); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("report written to %s\n", *outFile)
}
