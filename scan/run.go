package scan

import (
	"ssp/common"
	"sync"
)

func scanTask(url string, file string, vuln string) {
	var wg sync.WaitGroup

	if url != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Check(url)
		}()
	}

	if file != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			CheckFromFile(file)
		}()
	}

	if vuln != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ScanVuln(vuln)
			if common.Vulnum != 0 {
				vul(vuln)
			}
		}()
	}

	wg.Wait()
}

func Scanspring() {

	scanTask(*common.UrlPtr, *common.UrlfilePtr, *common.VulPtr)

	if *common.VulfilePtr != "" {

		VulFromFile(*common.VulfilePtr)
	}
}
