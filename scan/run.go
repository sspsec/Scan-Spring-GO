package scan

import (
	"ssp/common"
	"sync"
)

func Scanspring() {
	var wg sync.WaitGroup

	if *common.UrlPtr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Check(*common.UrlPtr)
		}()
	}

	if *common.UrlfilePtr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			CheckFromFile(*common.UrlfilePtr)
		}()
	}

	if *common.VulPtr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ScanVuln(*common.VulPtr)
			if common.Vulnum != 0 {
				vul(*common.VulPtr)
			}
			//vul(*common.VulPtr)
			//poc.CVE_2022_22965(*common.VulPtr)
		}()
	}

	if *common.VulfilePtr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			VulFromFile(*common.VulfilePtr)
		}()
	}

	wg.Wait()
}
