package cert

type Loader[T any] interface {
	Load(data []byte) (T, error)
}
