---
layout: page
title: Articles
permalink: /articles/
---

<div class="home">

  <ul class="post-list">
    {% for post in site.posts %}
      <table>
	      <tbody>
		      <tr>
			      <td>
				      <li>
					      <span class="post-meta">{{ post.date | date: "%b %-d, %Y" }}</span>
					      <h2>
						      <a class="post-link" href="{{ post.url | relative_url }}">{{ post.title | escape }}</a>
					      </h2>
					      {{ post.excerpt }}
				      </li>
			      </td>
		      </tr>
	      </tbody>
      </table>
    {% endfor %}
  </ul>

</div>
