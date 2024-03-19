package job

import (
	"context"
	"log"
)

func StartWorker(ctx context.Context, btfchan <-chan Job, jobchan <-chan Job) error {
	var job Job
	var ok bool
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case job, ok = <-btfchan:
			if !ok {
				return nil
			}
			break
		default:
			select {
			case job, ok = <-btfchan:
				if !ok {
					return nil
				}
				break
			case job, ok = <-jobchan:
				if !ok {
					return nil
				}
				break
			}
		}

		err := job.Do(ctx)
		if err != nil {
			if ch := job.Reply(); ch != nil {
				ch <- err
			} else {
				log.Printf("ERROR: %s", err)
			}
		}
	}
}
