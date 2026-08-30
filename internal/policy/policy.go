package policy

// Config содержит полную конфигурацию парольной политики и параметров выдачи.
type Config struct {
	Version int    `yaml:"version" json:"version"`
	Policy  Policy `yaml:"policy" json:"policy"`
	Issue   Issue  `yaml:"issue" json:"issue"`
}

// Length задаёт минимальную и максимальную длину пароля.
type Length struct {
	Min int `yaml:"min" json:"min"`
	Max int `yaml:"max" json:"max"`
}

// Class описывает именованный класс символов и его минимальное количество в пароле.
type Class struct {
	Name     string `yaml:"name" json:"name"`
	Alphabet string `yaml:"alphabet" json:"alphabet"`
	Min      int    `yaml:"min" json:"min"`
}

// Forbid содержит правила, запрещающие определённые свойства и подстроки пароля.
type Forbid struct {
	RepeatRun   int        `yaml:"repeat_run" json:"repeat_run"`
	RepeatTotal bool       `yaml:"repeat_total" json:"repeat_total"`
	Sequences   Sequences  `yaml:"sequences" json:"sequences"`
	Dictionary  Dictionary `yaml:"dictionary" json:"dictionary"`
	Context     Context    `yaml:"context" json:"context"`
}

// Forbid содержит правила, запрещающие определённые свойства и подстроки пароля.
type Sequences struct {
	Alphabet int      `yaml:"alphabet" json:"alphabet"`
	Keyboard int      `yaml:"keyboard" json:"keyboard"`
	Layouts  []string `yaml:"layouts" json:"layouts"`
}

// Dictionary задаёт параметры словарной проверки паролей.
type Dictionary struct {
	Path            string `yaml:"path" json:"path"`
	MinLength       int    `yaml:"min_length" json:"min_length"`
	CaseInsensitive bool   `yaml:"case_insensitive" json:"case_insensitive"`
	Leet            bool   `yaml:"leet" json:"leet"`
}

// Context задаёт параметры проверки пароля по значениям контекста.
type Context struct {
	MinLength int `yaml:"min_length" json:"min_length"`
}

// Issue задаёт параметры выдачи паролей, хранения истории и ротации.
type Issue struct {
	PoolSize    int     `yaml:"pool_size" json:"pool_size"`
	Store       string  `yaml:"store" json:"store"`
	History     History `yaml:"history" json:"history"`
	RotateAfter string  `yaml:"rotate_after" json:"rotate_after"`
}

// History задаёт размер защищённого окна и срок хранения истории паролей.
type History struct {
	Window int    `yaml:"window" json:"window"`
	Ttl    string `yaml:"ttl" json:"ttl"`
}

// Policy содержит правила генерации и проверки паролей.
type Policy struct {
	Name     string  `yaml:"name" json:"name"`
	Length   Length  `yaml:"length" json:"length"`
	Classes  []Class `yaml:"classes" json:"classes"`
	Exclude  string  `yaml:"exclude" json:"exclude"`
	Attempts int     `yaml:"attempts" json:"attempts"`
	Forbid   Forbid  `yaml:"forbid" json:"forbid"`
}
