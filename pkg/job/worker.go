package job

import (
	"context"
	"fmt"
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
		default:
			select {
			case job, ok = <-btfchan:
				if !ok {
					return nil
				}
			case job, ok = <-jobchan:
				if !ok {
					return nil
				}
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

func Submit(ctx context.Context, job Job, workChan chan<- Job) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case workChan <- job:
	}
	return nil
}

func Wait(job Job) error {
	reply := <-job.Reply()
	if err, ok := reply.(error); ok {
		return err
	}
	return nil
}

func WaitT[T any](job Job) (*T, error) {
	reply := <-job.Reply()
	switch v := reply.(type) {
	case error:
		return nil, v
	case *T:
		return v, nil
	default:
		return nil, fmt.Errorf("unexpected reply type: %T", v)
	}
}

func SubmitAndWait(ctx context.Context, job Job, workChan chan<- Job) error {
	if err := Submit(ctx, job, workChan); err != nil {
		return err
	}
	return Wait(job)
}

func SubmitAndWaitT[T any](ctx context.Context, job Job, workChan chan<- Job) (*T, error) {
	if err := Submit(ctx, job, workChan); err != nil {
		return nil, err
	}
	return WaitT[T](job)
}
