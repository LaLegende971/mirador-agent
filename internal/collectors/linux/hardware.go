//go:build linux

// Package linux implémente les collecteurs Linux : DMI/dmidecode pour le matériel,
// dpkg-query/rpm -qa pour les logiciels, apt/dnf pour les correctifs, /proc et /sys pour
// les métriques (cf. section 2.1 du cahier des charges).
package linux

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/LaLegende971/mirador-agent/internal/inventory"
)

func readFirstLine(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readDMI lit /sys/class/dmi/id/<field> ; c'est équivalent à dmidecode mais sans nécessiter
// les privilèges root que dmidecode réclame pour parcourir /dev/mem.
func readDMI(field string) string {
	return readFirstLine("/sys/class/dmi/id/" + field)
}

func osRelease() (name, version string) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "", ""
	}
	defer f.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		values[parts[0]] = strings.Trim(parts[1], `"`)
	}
	return values["PRETTY_NAME"], values["VERSION_ID"]
}

func cpuDescription() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func memoryTotalBytes() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseInt(fields[1], 10, 64)
				if err == nil {
					return kb * 1024
				}
			}
		}
	}
	return 0
}

// diskTotalBytes : capacité totale de la partition racine — même appel statfs que
// diskUsedPercent (metrics.go), cohérent avec « disk.root.used_pct ».
func diskTotalBytes(mount string) int64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(mount, &stat); err != nil {
		return 0
	}
	return int64(stat.Blocks) * int64(stat.Bsize)
}

// primaryIP se connecte (sans envoyer de paquet, UDP) à une adresse externe pour laisser le
// noyau choisir l'interface de sortie : c'est l'équivalent de « la passerelle par défaut
// remontée par l'agent » mentionné section 7 pour la découverte réseau best-effort.
func primaryIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	return addr.IP.String()
}

func CollectHardware(agentVersion string) inventory.HardwareInfo {
	osName, osVersion := osRelease()
	fqdn, _ := os.Hostname()
	if out, err := exec.Command("hostname", "-f").Output(); err == nil {
		if v := strings.TrimSpace(string(out)); v != "" {
			fqdn = v
		}
	}

	return inventory.HardwareInfo{
		FQDN:         fqdn,
		OSFamily:     "linux",
		OSName:       osName,
		OSVersion:    osVersion,
		Vendor:       readDMI("sys_vendor"),
		Model:        readDMI("product_name"),
		Serial:       readDMI("product_serial"),
		CPUDesc:      cpuDescription(),
		MemoryBytes:  memoryTotalBytes(),
		DiskBytes:    diskTotalBytes("/"),
		PrimaryIP:    primaryIP(),
		AgentVersion: agentVersion,
	}
}
