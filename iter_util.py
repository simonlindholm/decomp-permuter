def batch(it, batch_size):
    while True:
        batch = []
        for i in range(batch_size):
            v = next(it, None)
            if v == None:
                if len(batch) != 0:
                    yield batch
                return

            batch.append(v)
        yield batch