# LimaCharlie.io Sample Detection & Response Rules.

The rules contained in this repository are aimed at providing learning material for the creation
of D&R rules used in [LimaCharlie.io](https://limacharlie.io).

Rules are included in JSON format (used by the REST interface) and YAML format (used as a simplified view in the web interface).

## Documentation
The documentation itself on which operators are supported, including which automated actions
you can take in response to a detection match (the R in Detection & Response) can be found
with the rest of the detailed documentation [here](http://doc.limacharlie.io/dr.html).

## High Level Guidelines
Events in LC are processed in real-time, but the performance of the D&R rules can vary. This is why
there are a few general rules one should follow in order to maintain the best performance possible.

### Filter Out Early
Rules are interpreted in the order they have been specified. This is particularly relevant for
rules using the `and` and `or` operator. In the case of an `and`, the first component is evaluated
and if it does not match, the other components are not evaluated.

This means you should try to use the first component to eliminated as many events as possible.

For example let's take the [win-suspicious-exec-location](win-suspicious-exec-location.yaml) rule.

```yaml
op: and
rules:
- events:
  - NEW_PROCESS
  - CODE_IDENTITY
  op: is windows
- case sensitive: false
  op: matches
  path: event/FILE_PATH
  re: .*(?:(?:windows\\(?:(?:system32)|(?:syswow64))\\tasks\\)|(?:recycle)|(?:\\windows\\fonts\\)|(?:\\windows\\help\\)|(?:\\windows\\wbem\\)|(?:\\windows\\addins\\)|(?:\\windows\\debug\\)|(?:\\perflogs\\)).*
```

The most expensive (in terms of performance) part of this rule is the regular expression. To avoid
trying to apply the regular expression to events we ***know*** cannot possibly be relevant we
include a filter before the regular expression using an `and`.

This first component checks a few things. First, is this event even coming from a Windows host.
Since this rule only makes sense on Windows, we eliminate all other platforms from evaluation.

Then we check if the event type is interesting. In this case, since we are looking at locations on disk
of executables, we really only care about `NEW_PROCESS` (a process is starting)
and `CODE_IDENTITY` (hash and file path of an executable the first time it is loaded) events. This means
that if a DNS event comes through, we won't attempt to apply the regular expression, making the rule faster.

### Wilcard Paths
Many operators make use of a "path" through the event to select a specific value found in the event
for comparison. For example, the [win-suspicious-command-line](win-suspicious-command-line.yaml) detection:

```yaml
op: and
rules:
- event: NEW_PROCESS
  op: is windows
- case sensitive: false
  op: matches
  path: event/COMMAND_LINE
  re: .*(?:\xE2\x80\x8F).*
```

The first component applies an early filter as described in the previous section.

The second component looks for a regular expression for the value in `event/COMMAND_LINE`.
This path will select the value like this:
```json
{
    "event": {
        "COMMAND_LINE": "this-value-is-selected",
        "OTHER_DATA": "this-is-not-selected"
    },
    "this-is-not-selected-either": "test"
}
```

To figure out the exact path you want to use in your detection, have a look at samples
of the data you get from your sensors, that way you'll be sure to get exactly what you want.

The paths also support wildcards. Those, however, should be used carefully as they may
degrade the performance of your rule. The two supported wildcards are `*` and `?`. The first,
`*` will match zero or more sub-levels with any name in the event data. This is useful for looking for a value
that could be found anywhere in the event. The second, `?` looks for exactly-one sub-level with any name in the
event data.

Matching with `*`, especially for rare values will result in a large performance penalty as
every level of the event is searched.
